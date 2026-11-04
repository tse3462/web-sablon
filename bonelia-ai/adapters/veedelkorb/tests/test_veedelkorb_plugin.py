"""The VeedelKorb adapter as an optional, separately installed plugin."""

import ast
import socket
import threading
import time
from pathlib import Path

import httpx
import uvicorn

import bonelia_adapter_veedelkorb as vk
from bonelia.adapters.registry import LoadedAdapter, discover, load_server_adapters, register_adapter_tools
from bonelia.monitor.client import ServerClient, enroll
from bonelia.repair.builtin_tools import default_registry
from bonelia.security import crypto
from bonelia.server.app import create_app
from bonelia.server.config import ServerConfig
from bonelia.server.store import Store
from conftest import fixture_json

PKG = Path(vk.__file__).parent


def test_plugin_uses_only_the_public_plugin_api():
    bad = []
    for p in PKG.rglob("*.py"):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            mods = []
            if isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            elif isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            bad += [m for m in mods if m.startswith("bonelia") and m != "bonelia.plugin_api" and not m.startswith("bonelia_adapter")]
    assert bad == []


def test_entry_point_is_discovered_when_installed():
    eps = {ep.name: ep for ep in discover()}
    assert "veedelkorb" in eps and eps["veedelkorb"].load() is vk.PLUGIN


def test_disabled_by_default_and_not_configured_without_secret():
    res = load_server_adapters({}, {})
    assert res["veedelkorb"].status == "disabled"
    res = load_server_adapters({"veedelkorb": {"enabled": True, "url": "https://x.supabase.co"}}, {})
    assert res["veedelkorb"].status == "not_configured"


def test_create_with_server_side_secret_only_and_no_repair_in_production():
    env = {vk.ENV_TOKEN: "tok", vk.ENV_TEST_SERVICE_KEY: "svc", "OPENAI_API_KEY": "sk-x"}
    res = load_server_adapters({"veedelkorb": {"enabled": True, "url": "https://x.supabase.co", "environment": "production"}}, env)
    la = res["veedelkorb"]
    assert la.status == "available" and la.instance.safe_action is None  # no repair executor outside TEST
    res = load_server_adapters({"veedelkorb": {"enabled": True, "url": "https://x.supabase.co", "environment": "test"}}, env)
    assert res["veedelkorb"].instance.safe_action is not None
    reg = default_registry()
    register_adapter_tools(res, reg, enabled=set())
    assert reg.get("veedelkorb.retry_failed_notifications").enabled is False  # still off until the owner enables it


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_plugin_through_core_server_end_to_end(tmp_path):
    adapter = vk.VeedelKorbAdapter("https://example.supabase.co", "server-only-token",
                                   transport=httpx.MockTransport(lambda r: httpx.Response(503, json=fixture_json("saglik_degraded.json"))))
    cfg = ServerConfig(data_dir=tmp_path / "srv", ollama_url=None)
    cfg.data_dir.mkdir()
    store = Store(cfg.db_path)
    tenant = store.create_tenant("VeedelKorb test")
    adapters = {"veedelkorb": LoadedAdapter("veedelkorb", "available", vk.MANIFEST, adapter, {tenant})}
    reg = default_registry()
    register_adapter_tools(adapters, reg, set())
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(cfg, store=store, registry=reg, adapters=adapters,
                                                      server_key=crypto.generate_keypair()), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)
    try:
        url = f"http://127.0.0.1:{port}"
        client = ServerClient(enroll(url, store.create_enrollment_code(tenant, ["diagnose", "adapter:veedelkorb"]), "USB 03"))
        res = client.adapter_health("veedelkorb", "tr")
        assert res["collector_status"]["veedelkorb:ai_control"] == "disabled_or_unknown"
        assert any("notify" in e["title"] for e in res["events"]) and len(res["diagnoses"]) == len(res["events"])
        assert "server-only-token" not in str(res)
        res = client.run_tool("veedelkorb.retry_failed_notifications", {}, dry_run=False)
        assert res["outcome"] == "denied"
    finally:
        server.should_exit = True
        t.join(5)
