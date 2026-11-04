"""USB <-> Server integration, security and failure tests over real HTTP sockets."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from bonelia.ai.costs import PriceTable
from bonelia.ai.providers import OllamaProvider
from bonelia.ai.router import HybridRouter
from bonelia.adapters.veedelkorb import VeedelKorbAdapter
from bonelia.contracts import RiskLevel
from bonelia.monitor.client import FakeServerError, ServerClient, ServerError, ServerUnavailable, check_server_url, enroll
from bonelia.monitor.offline_queue import OfflineQueue
from bonelia.monitor.portable import PortableHome
from bonelia.monitor.reports import load_encrypted
from bonelia.monitor.session import Session
from bonelia.repair.builtin_tools import default_registry
from bonelia.security import crypto
from bonelia.server.app import create_app
from bonelia.server.config import ServerConfig
from bonelia.server.store import Store
from tests.conftest import ServerThread, fixture_json, free_port
from tests.fakes import fake_ollama

PASS = "test passphrase 123"


@pytest.fixture
def env(tmp_path):
    """Home AI server + fake local model + two tenants."""
    ollama_state = {"mode": "ok"}
    ollama = ServerThread(fake_ollama(ollama_state)).__enter__()
    cfg = ServerConfig(data_dir=tmp_path / "server", ollama_url=ollama.url, veedelkorb={"tenant_id": None})
    cfg.data_dir.mkdir()
    store = Store(cfg.db_path)
    t_a = store.create_tenant("Kunde A (VeedelKorb)", environment="test")
    t_b = store.create_tenant("Kunde B", environment="production")
    cfg.veedelkorb["tenant_id"] = t_a
    vk = VeedelKorbAdapter("https://example.supabase.co", "server-only-token",
                           transport=httpx.MockTransport(lambda r: httpx.Response(503, json=fixture_json("saglik_degraded.json"))))
    registry = default_registry()
    # max_ai_events=25: host metric events (e.g. a full disk on a CI runner) must not crowd out the controlled test error
    rt = HybridRouter(OllamaProvider(ollama.url, timeout_s=2), None, PriceTable(), store, lambda: registry.ids(), max_ai_events=25)
    key = crypto.generate_keypair()
    port = free_port()
    srv = ServerThread(create_app(cfg, store=store, router=rt, registry=registry, veedelkorb=vk, server_key=key), port).__enter__()
    ctx = {"cfg": cfg, "store": store, "a": t_a, "b": t_b, "srv": srv, "key": key, "ollama": ollama_state, "port": port,
           "registry": registry, "router": rt, "vk": vk}
    yield ctx
    srv.__exit__(None, None, None)
    ollama.__exit__(None, None, None)


def usb(tmp_path: Path, env, name: str, tenant: str, scopes=("diagnose",)) -> Session:
    """Simulate one USB copy: its own folder, own key, own vault."""
    home = PortableHome(tmp_path / name).ensure()
    code = env["store"].create_enrollment_code(tenant, list(scopes))
    creds = enroll(env["srv"].url, code, name)
    crypto.Vault(home.vault_path).save(creds, PASS)
    s = Session(home=home, lang="de")
    s.unlock(PASS)
    return s


def controlled_error_log(tmp_path: Path) -> str:
    p = tmp_path / "poskasse.log"
    p.write_text("2026-11-04 10:00:01 INFO start\n"
                 "2026-11-04 10:00:05 ERROR Druckauftrag fehlgeschlagen: printdrv.dll access violation 0xc0000005 user anna@firma.de\n",
                 encoding="utf-8")
    return str(p)


# ----------------------------------------------------------------------------- happy path


def test_v01_scenario_scan_analyze_report(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    assert s.server_status()["connected"] is True
    s.scan(mode="quick", log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    rep = s.analyze(allow_cloud=False)
    f = next(x for x in rep["findings"] if x["program"] == "poskasse")
    assert f["analysis_source"] == "ollama:qwen2.5:7b-instruct"
    assert any("printdrv.dll" in c["cause"] for c in f["likely_causes"]) and f["definitive"] is False
    assert rep["interventions"] == []  # nothing was changed
    # PII never left the customer machine
    sent = json.dumps(env["ollama"]["requests"])
    assert "anna@firma.de" not in sent
    # USB holds only an encrypted report
    files = list((s.home.root / "reports").glob("*.bnr"))
    assert files and b"poskasse" not in files[-1].read_bytes()
    assert load_encrypted(files[-1], s.data_key)["scan_id"] == rep["scan_id"]
    # export of plaintext happens only on request
    out = s.export_last(tmp_path / "desktop")
    assert {p.suffix for p in out} == {".json", ".txt", ".html"}


def test_same_package_runs_on_next_computer(tmp_path, env):
    """Two USB copies of the same package = two independent devices."""
    s1 = usb(tmp_path, env, "USB-01", env["a"])
    s2 = usb(tmp_path, env, "USB-02", env["a"])
    assert s1.creds.device_id != s2.creds.device_id
    assert s1.creds.private_key.public_key() != s2.creds.private_key.public_key()
    for s in (s1, s2):
        s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
        assert s.analyze()["findings"]


# ----------------------------------------------------------------------------- security


def test_enrollment_code_is_single_use(tmp_path, env):
    code = env["store"].create_enrollment_code(env["a"], ["diagnose"])
    enroll(env["srv"].url, code, "x")
    with pytest.raises(ServerError) as e:
        enroll(env["srv"].url, code, "y")
    assert e.value.status == 403


def test_expired_enrollment_code(tmp_path, env):
    code = env["store"].create_enrollment_code(env["a"], ["diagnose"], ttl_minutes=-1)
    with pytest.raises(ServerError):
        enroll(env["srv"].url, code, "x")


def test_unsigned_tampered_and_replayed_requests_rejected(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    url = env["srv"].url
    assert httpx.get(f"{url}/v1/events").status_code == 401
    body = b"{}"
    h = crypto.sign_request(s.creds.private_key, s.creds.device_id, "GET", "/v1/events", b"")
    assert httpx.get(f"{url}/v1/events", headers=h).status_code == 200
    assert httpx.get(f"{url}/v1/events", headers=h).status_code == 401  # replay
    h2 = crypto.sign_request(s.creds.private_key, s.creds.device_id, "POST", "/v1/chat", b'{"question":"a"}')
    assert httpx.post(f"{url}/v1/chat", headers=h2, content=b'{"question":"b"}').status_code == 401  # tampered body
    other = crypto.generate_keypair()
    h3 = crypto.sign_request(other, s.creds.device_id, "GET", "/v1/events", b"")
    assert httpx.get(f"{url}/v1/events", headers=h3).status_code == 401  # stolen device id, wrong key
    actions = [r["action"] for r in env["store"].audit_log()]
    assert "auth.replay" in actions and "auth.bad_signature" in actions
    del body


def test_lost_usb_is_revoked_without_affecting_others(tmp_path, env):
    lost = usb(tmp_path, env, "USB-lost", env["a"])
    other = usb(tmp_path, env, "USB-other", env["a"])
    env["store"].revoke_device(lost.creds.device_id)
    with pytest.raises(ServerError) as e:
        lost.client.events()
    assert e.value.detail == "device_revoked"
    assert isinstance(other.client.events(), list)
    # the lost stick is useless without its passphrase
    with pytest.raises(ValueError):
        crypto.Vault(lost.home.vault_path).load("guessing passphrase")


def test_tenant_isolation(tmp_path, env):
    a = usb(tmp_path, env, "USB-A", env["a"])
    b = usb(tmp_path, env, "USB-B", env["b"], scopes=("diagnose", "adapter:veedelkorb"))
    a.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    a.analyze()
    assert a.client.events() and b.client.events() == []
    with pytest.raises(ServerError) as e:  # adapter belongs to tenant A
        b.client.veedelkorb_health("tr")
    assert e.value.detail == "adapter_not_assigned_to_tenant"
    assert env["store"].events(env["b"]) == []


def test_scope_enforcement(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"], scopes=("diagnose",))
    with pytest.raises(ServerError) as e:
        s.client.veedelkorb_health("tr")
    assert e.value.status == 403


def test_fake_server_is_detected(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    impostor = ServerThread(create_app(env["cfg"], store=env["store"], router=env["router"], registry=env["registry"],
                                       server_key=crypto.generate_keypair())).__enter__()
    try:
        s.creds.server_url = impostor.url
        fake_client = ServerClient(s.creds)
        with pytest.raises(FakeServerError):
            fake_client.health()
        s.client = fake_client
        s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
        rep = s.analyze()
        assert any("gefälschter Server" in n for n in rep["notices"])
    finally:
        impostor.__exit__(None, None, None)


def test_enrollment_pins_expected_server_key(tmp_path, env):
    code = env["store"].create_enrollment_code(env["a"], ["diagnose"])
    with pytest.raises(FakeServerError):
        enroll(env["srv"].url, code, "x", expected_server_key_b64=crypto.public_key_b64(crypto.generate_keypair()))


def test_plain_http_only_for_loopback_or_tailscale():
    assert check_server_url("http://127.0.0.1:8742") and check_server_url("http://100.101.102.103:8742")
    assert check_server_url("https://ai.example.com")
    for bad in ("http://192.168.1.10:8742", "http://example.com", "ftp://x", "https://x/path"):
        with pytest.raises(ValueError):
            check_server_url(bad)


def test_prompt_injection_cannot_produce_commands(tmp_path, env):
    env["ollama"]["mode"] = "obey"
    s = usb(tmp_path, env, "USB-01", env["a"])
    s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    res = s.client.analyze(s.last_scan.events, None, False, "en")
    for d in res.diagnoses:
        assert d.is_definitive is False
        assert all(r.tool_id in (None, "generic.collect_snapshot") for r in d.recommendations)
    ai = next(d for d in res.diagnoses if d.produced_by.startswith("ollama"))
    assert any("unknown tool" in w for w in ai.warnings) and any("command-like" in w for w in ai.warnings)


def test_oversized_body_rejected(tmp_path, env):
    assert httpx.post(f"{env['srv'].url}/v1/enroll", content=b"x" * 1_100_000).status_code == 413


def test_audit_chain_and_minimal_content(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    s.analyze()
    store = env["store"]
    assert store.verify_audit_chain()
    assert "printdrv" not in json.dumps(store.audit_log())  # audit holds metadata, not evidence
    store._x("update audit set detail='{}' where id=(select min(id) from audit)")
    assert not store.verify_audit_chain()  # tampering is detectable


# ----------------------------------------------------------------------------- failures


def test_server_down_then_back_queue_drains(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    env["srv"].__exit__(None, None, None)
    s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    rep = s.analyze()
    assert rep["ai_mode"] == "rules-offline" and any("Offline" in n for n in rep["notices"])
    assert rep["findings"][0]["analysis_source"] == "rules"  # local diagnosis still works
    assert OfflineQueue(s.home.path("queue"), s.data_key).size() == 1
    with pytest.raises(ServerUnavailable):
        s.client.run_tool("windows.restart_service", {"service_name": "Spooler"}, dry_run=True)  # no remote action offline
    env["srv"] = ServerThread(create_app(env["cfg"], store=env["store"], router=env["router"], registry=env["registry"],
                                         veedelkorb=env["vk"], server_key=env["key"]), env["port"]).__enter__()
    s.analyze()
    assert OfflineQueue(s.home.path("queue"), s.data_key).size() == 0


@pytest.mark.parametrize("mode", ["slow", "garbage", "error"])
def test_ai_failures_fall_back_to_rules(tmp_path, env, mode):
    env["ollama"]["mode"] = mode
    s = usb(tmp_path, env, "USB-01", env["a"])
    s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    rep = s.analyze()
    assert all(f["analysis_source"] == "rules" for f in rep["findings"])
    assert any("Rückfall" in n for n in rep["notices"])


def test_offline_queue_is_bounded_and_survives_corruption(tmp_path):
    from bonelia.contracts import AppIdentity, DiagnosticEvent

    q = OfflineQueue(tmp_path / "q", crypto.DataKey(b"k" * 32))
    ev = DiagnosticEvent(app=AppIdentity(app_id="a", name="a"), title="t", fingerprint="f")
    dropped = sum(q.push([ev]) for _ in range(205))
    assert q.size() == 200 and dropped == 5
    next(iter(sorted((tmp_path / "q").glob("*.bnq")))).write_bytes(b"corrupt")
    sent, failed = q.drain(lambda evs: None)
    assert sent == 199 and failed == 1 and q.size() == 0


# ----------------------------------------------------------------------------- adapters, tools, chat


def test_veedelkorb_read_only_analysis(tmp_path, env):
    s = usb(tmp_path, env, "USB-03", env["a"], scopes=("diagnose", "adapter:veedelkorb"))
    res = s.client.veedelkorb_health("tr")
    assert res["collector_status"]["veedelkorb:ai_control"] == "disabled_or_unknown"
    titles = [e["title"] for e in res["events"]]
    assert any("notify" in t for t in titles) and len(res["diagnoses"]) == len(res["events"])
    assert "server-only-token" not in json.dumps(res)


def test_tool_gateway_over_api(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"], scopes=("diagnose", "repair:windows", "repair:veedelkorb"))
    tools = {t["tool_id"]: t for t in s.client.tools()}
    assert tools["windows.restart_service"]["risk_level"] == int(RiskLevel.ADMIN_APPROVED)
    dry = s.client.run_tool("windows.restart_service", {"service_name": "PosKasseSync"}, dry_run=True)
    assert dry["outcome"] == "dry_run_only"
    with pytest.raises(ServerError) as e:
        s.client.run_tool("windows.restart_service", {"service_name": "PosKasseSync"}, dry_run=False)
    assert e.value.status == 409
    res = s.client.run_tool("veedelkorb.retry_failed_notifications", {}, dry_run=False)
    assert res["outcome"] == "denied" and res["reasons"] == ["tool_disabled"]
    assert s.client.run_tool("powershell.run", {"cmd": "whoami"}, dry_run=False)["reasons"] == ["unknown_tool"]
    bad = s.client.run_tool("windows.restart_service", {"service_name": "x; shutdown /s"}, dry_run=True)
    assert bad["outcome"] == "denied"


def test_chat_is_grounded(tmp_path, env):
    s = usb(tmp_path, env, "USB-01", env["a"])
    assert s.client.chat("Neden çöküyor?", "tr")["grounded_on"] == 0
    s.scan(log_paths=[controlled_error_log(tmp_path)], include_eventlog=False)
    s.analyze()
    res = s.client.chat("Son yarım saatteki hataları incele.", "tr")
    assert res["grounded_on"] >= 1 and "printdrv" in res["answer"]
