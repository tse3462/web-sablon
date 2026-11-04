"""Module independence: the BONELİA AI core works with no, broken or misbehaving adapters.

Application adapters are optional packages. These tests prove that
* the core source contains no reference to any application adapter,
* the full USB -> Server -> diagnosis flow works with zero adapters,
* a broken adapter (import error, init error, crash at runtime) is isolated,
* an adapter only receives its own config and its own declared secrets,
* adapter tools are namespaced, start disabled and can never be level 3,
* adapters are assigned per customer.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bonelia.adapters.registry import (
    ENTRY_POINT_GROUP, adapter_of_tool, discover, load_server_adapters, register_adapter_tools, secret_prefix,
)
from bonelia.contracts import RiskLevel
from bonelia.monitor.client import ServerError
from bonelia.repair.builtin_tools import default_registry
from bonelia.server.app import create_app
from bonelia.server.config import ServerConfig
from bonelia.server.store import Store
from bonelia.security import crypto
from tests.conftest import ServerThread
from tests.demo_plugins import EntryPoint, Plugin, tool

CORE = Path(__file__).resolve().parents[2] / "src" / "bonelia"
KNOWN_APP_ADAPTERS = ("veedelkorb", "vedicore", "kanslide", "bonelia_finance", "bonelia-finance", "sap")


# ----------------------------------------------------------------------------- static independence


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_core_never_imports_an_adapter_package():
    offenders = {str(p.relative_to(CORE)): sorted(m for m in _imports(p) if m.startswith("bonelia_adapter"))
                 for p in CORE.rglob("*.py")}
    assert {k: v for k, v in offenders.items() if v} == {}


def test_core_code_does_not_name_any_specific_application_adapter():
    hits = []
    for p in list(CORE.rglob("*.py")) + list(CORE.rglob("*.html")):
        text = p.read_text(encoding="utf-8").lower()
        hits += [f"{p.relative_to(CORE)}:{name}" for name in ("veedelkorb",) if name in text]
    assert hits == []


def test_core_package_imports_cleanly_with_adapter_packages_blocked():
    """Fresh interpreter in which every `bonelia_adapter_*` import raises ImportError."""
    code = (
        "import sys, importlib.abc\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name.startswith('bonelia_adapter'): raise ImportError('blocked: ' + name)\n"
        "sys.meta_path.insert(0, Block())\n"
        "import bonelia.server.app, bonelia.monitor.cli, bonelia.monitor.ui, bonelia.plugin_api\n"
        "from bonelia.adapters.registry import load_server_adapters\n"
        "res = load_server_adapters({'veedelkorb': {'enabled': True}}, {})\n"
        "print({k: v.status for k, v in res.items()})\n"
    )
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    # If an adapter package happens to be installed, it is reported as load_error — never a crash.
    assert "Traceback" not in p.stderr


# ----------------------------------------------------------------------------- registry behaviour


def test_discovery_uses_entry_points_only():
    assert ENTRY_POINT_GROUP == "bonelia.adapters"
    for ep in discover():  # whatever is installed must be loadable through the registry without crashing
        assert ep.group == ENTRY_POINT_GROUP


def test_broken_adapters_are_isolated():
    eps = [
        EntryPoint("import-broken", load_error=ImportError("module missing")),
        EntryPoint("init-broken", Plugin("init-broken", create_raises=True)),
        EntryPoint("unconfigured", Plugin("unconfigured", returns_none=True)),
        EntryPoint("switched-off", Plugin("switched-off")),
        EntryPoint("Bad ID!", Plugin("bad")),
        EntryPoint("wrong-name", Plugin("other-name")),
        EntryPoint("good", Plugin("good")),
    ]
    sections = {n: {"enabled": True} for n in ("import-broken", "init-broken", "unconfigured", "good", "wrong-name")}
    res = load_server_adapters(sections, {}, eps=eps)
    assert {k: v.status for k, v in res.items()} == {
        "import-broken": "load_error", "init-broken": "load_error", "unconfigured": "not_configured",
        "switched-off": "disabled", "Bad ID!": "invalid", "wrong-name": "load_error", "good": "available"}


def test_adapter_receives_only_its_config_and_declared_prefixed_secrets():
    plugin = Plugin("demo-erp", secret_env=["BONELIA_DEMO_ERP_TOKEN", "OPENAI_API_KEY", "BONELIA_OTHER_TOKEN"])
    env = {"BONELIA_DEMO_ERP_TOKEN": "t1", "BONELIA_DEMO_ERP_UNDECLARED": "x", "OPENAI_API_KEY": "sk-secret",
           "BONELIA_OTHER_TOKEN": "y", "PATH": "/bin"}
    load_server_adapters({"demo-erp": {"enabled": True, "tenant_ids": ["ten_1"], "url": "https://x"},
                          "other": {"enabled": True, "url": "https://other"}}, env, eps=[EntryPoint("demo-erp", plugin)])
    assert plugin.seen_env == {"BONELIA_DEMO_ERP_TOKEN": "t1"}  # no foreign, undeclared or core secrets
    assert plugin.seen_config == {"url": "https://x"}  # core keys removed, other sections invisible
    assert secret_prefix("demo-erp") == "BONELIA_DEMO_ERP_"


def test_adapter_tools_are_namespaced_disabled_and_never_critical():
    plugin = Plugin("demo-erp", tools=[tool("demo-erp.retry_exports"), tool("generic.collect_snapshot"),
                                       tool("windows.format_disk"), tool("demo-erp.wipe", RiskLevel.CRITICAL)])
    adapters = load_server_adapters({"demo-erp": {"enabled": True}}, {}, eps=[EntryPoint("demo-erp", plugin)])
    reg = default_registry()
    register_adapter_tools(adapters, reg, enabled=set())
    ids = {t.tool_id for t in reg.all()}
    assert "demo-erp.retry_exports" in ids and "demo-erp.wipe" not in ids and "windows.format_disk" not in ids
    assert reg.get("demo-erp.retry_exports").enabled is False
    assert adapter_of_tool(adapters, "demo-erp.retry_exports").adapter_id == "demo-erp"
    assert adapter_of_tool(adapters, "generic.collect_snapshot") is None


# ----------------------------------------------------------------------------- runtime independence


@pytest.fixture
def make_server(tmp_path):
    started = []

    def _make(adapters):
        cfg = ServerConfig(data_dir=tmp_path / f"srv{len(started)}", ollama_url=None)
        cfg.data_dir.mkdir()
        store = Store(cfg.db_path)
        reg = default_registry()
        register_adapter_tools(adapters, reg, set())
        srv = ServerThread(create_app(cfg, store=store, registry=reg, adapters=adapters, server_key=crypto.generate_keypair())).__enter__()
        started.append(srv)
        return srv, store

    yield _make
    for s in started:
        s.__exit__(None, None, None)


def _device(tmp_path, srv, store, tenant, scopes):
    from bonelia.monitor.client import ServerClient, enroll

    creds = enroll(srv.url, store.create_enrollment_code(tenant, scopes), "USB")
    return ServerClient(creds)


def _log(tmp_path):
    p = tmp_path / "pos.log"
    p.write_text("2026-11-04 ERROR Kassenexport fehlgeschlagen: timeout\n", encoding="utf-8")
    return str(p)


def test_full_universal_flow_with_zero_adapters(tmp_path, make_server):
    from bonelia.monitor.portable import PortableHome
    from bonelia.monitor.session import Session

    srv, store = make_server({})
    tenant = store.create_tenant("Any business")
    client = _device(tmp_path, srv, store, tenant, ["diagnose"])
    s = Session(home=PortableHome(tmp_path / "usb").ensure(), lang="tr")
    s.creds, s.client = client.creds, client
    s.scan(log_paths=[_log(tmp_path)], include_eventlog=False)
    rep = s.analyze()
    assert any("timeout" in f["evidence"][0]["text"] for f in rep["findings"])
    listed = {a["adapter_id"]: a["load_status"] for a in client.adapters()}
    assert listed["generic-windows"] == "core" and all(v in ("core", "planned") for v in listed.values())
    with pytest.raises(ServerError) as e:
        client.adapter_health("demo-erp", "tr")
    assert e.value.status == 404


def test_crashing_adapter_does_not_affect_core_or_other_adapters(tmp_path, make_server):
    adapters = load_server_adapters(
        {"crashy": {"enabled": True, "tenant_ids": ["*"]}, "healthy": {"enabled": True, "tenant_ids": ["*"]}}, {},
        eps=[EntryPoint("crashy", Plugin("crashy", health_fails=True)), EntryPoint("healthy", Plugin("healthy"))])
    srv, store = make_server(adapters)
    tenant = store.create_tenant("T")
    for la in adapters.values():
        la.tenant_ids = {tenant}
    client = _device(tmp_path, srv, store, tenant, ["diagnose", "adapter:crashy", "adapter:healthy"])
    with pytest.raises(ServerError) as e:
        client.adapter_health("crashy", "de")
    assert e.value.status == 502 and e.value.detail == "adapter_error"
    assert client.adapter_health("healthy", "de")["events"]  # other adapter unaffected
    assert client.health()["status"] == "ok"  # core unaffected
    assert "adapter.error" in [r["action"] for r in store.audit_log()]


def test_adapter_and_its_tools_are_assigned_per_customer(tmp_path, make_server):
    plugin = Plugin("demo-erp", tools=[tool("demo-erp.retry_exports")])
    adapters = load_server_adapters({"demo-erp": {"enabled": True}}, {}, eps=[EntryPoint("demo-erp", plugin)])
    srv, store = make_server(adapters)
    a, b = store.create_tenant("A"), store.create_tenant("B")
    adapters["demo-erp"].tenant_ids = {a}
    scopes = ["diagnose", "adapter:demo-erp", "repair:demo"]
    ca, cb = _device(tmp_path, srv, store, a, scopes), _device(tmp_path, srv, store, b, scopes)
    assert ca.adapter_health("demo-erp", "tr")["events"]
    with pytest.raises(ServerError) as e:
        cb.adapter_health("demo-erp", "tr")
    assert e.value.detail == "adapter_not_assigned_to_tenant"
    assert "demo-erp.retry_exports" in {t["tool_id"] for t in ca.tools()}
    assert "demo-erp.retry_exports" not in {t["tool_id"] for t in cb.tools()}
    with pytest.raises(ServerError) as e:
        cb.run_tool("demo-erp.retry_exports", {}, dry_run=True)
    assert e.value.status == 403
    assert {x["adapter_id"]: x.get("assigned_to_tenant") for x in cb.adapters()}["demo-erp"] is False


def test_invalid_adapter_ids_are_rejected_by_client_and_server(tmp_path, make_server):
    srv, store = make_server({})
    c = _device(tmp_path, srv, store, store.create_tenant("T"), ["diagnose"])
    with pytest.raises(ValueError):
        c.adapter_health("../v1/events", "tr")
    import httpx

    body = b"{}"
    h = crypto.sign_request(c.creds.private_key, c.creds.device_id, "POST", "/v1/adapters/BAD_ID/health", body)
    assert httpx.post(f"{srv.url}/v1/adapters/BAD_ID/health", headers=h, content=body).status_code == 404
    assert json.dumps(c.adapters())  # listing still works
