"""Control panel: local-only access, overview, findings with diagnoses, repairs, level change, revoke."""

from datetime import timedelta

from fastapi.testclient import TestClient

from bonelia.contracts import AppIdentity, Diagnosis, DiagnosticEvent, Hypothesis, Triage, utcnow
from bonelia.server.dashboard import create_dashboard_app
from bonelia.server.store import Store

TOKEN = "d" * 32


def setup(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    t = store.create_tenant("Filiale Ehrenfeld")
    usb = store.redeem_enrollment(store.create_enrollment_code(t, ["diagnose", "install:agent"]), "USB 01", "pk-usb")["device_id"]
    agent = store.create_agent_device(t, "KASSE-1", "pk-agent", usb)["device_id"]
    store.touch_device(agent)
    store.set_device_status(agent, {"cycles": 3, "repairs": ["windows.start_service:executed_verified"]})
    ev = store.save_event(t, agent, DiagnosticEvent(app=AppIdentity(app_id="svc", name="Druckwarteschlange"),
                                                    title="Hizmet durmuş: Druckwarteschlange", fingerprint="f1",
                                                    triage=Triage.important, repair_tool="windows.start_service"))
    store.save_event(t, agent, DiagnosticEvent(app=AppIdentity(app_id="x", name="x"), title="noise", fingerprint="f2",
                                               triage=Triage.harmless))
    store.save_diagnosis(t, Diagnosis(event_id=ev.event_id, produced_by="ollama:qwen2.5:3b-instruct", summary="Spooler stopped",
                                      hypotheses=[Hypothesis(cause="Service crashed", confidence="medium")]))
    store.audit("gateway", "tool.executed", {"tool_id": "windows.start_service", "params": {"service_name": "Spooler"},
                                             "outcome": "executed_verified", "verified": True}, tenant_id=t, device_id=agent)
    c = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999")
    return store, c, t, usb, agent


H = {"x-ui-token": TOKEN}


def test_panel_is_local_and_token_protected(tmp_path):
    _, c, *_ = setup(tmp_path)
    assert c.get("/").status_code == 200 and "Kontrol Paneli" in c.get("/").text
    assert c.get("/api/overview").status_code == 403
    assert c.get("/api/overview", headers={"x-ui-token": TOKEN, "host": "evil.example:9999"}).status_code == 403


def test_overview_findings_and_repairs(tmp_path):
    store, c, t, usb, agent = setup(tmp_path)
    o = c.get("/api/overview", headers=H).json()
    devs = {d["id"]: d for d in o["devices"]}
    assert devs[agent]["kind"] == "agent" and devs[agent]["online"] and devs[usb]["kind"] == "usb"
    assert o["tenants"][0]["online"] == 1 and o["tenants"][0]["important_24h"] == 1
    f = c.get("/api/findings", headers=H).json()["findings"]
    assert [x["title"] for x in f] == ["Hizmet durmuş: Druckwarteschlange"]  # harmless never shown
    assert f[0]["diagnosis"]["produced_by"].startswith("ollama") and f[0]["device"] == "KASSE-1"
    r = c.get("/api/repairs", headers=H).json()["repairs"]
    assert r[0]["outcome"] == "executed_verified" and r[0]["device"] == "KASSE-1"


def test_offline_agent_is_shown_offline(tmp_path):
    store, c, t, usb, agent = setup(tmp_path)
    store._x("update devices set last_seen_at=? where id=?", ((utcnow() - timedelta(hours=2)).isoformat(), agent))
    devs = {d["id"]: d for d in c.get("/api/overview", headers=H).json()["devices"]}
    assert devs[agent]["online"] is False


def test_level_change_and_revoke(tmp_path):
    store, c, t, usb, agent = setup(tmp_path)
    assert c.post(f"/api/tenants/{t}/repair-level", json={"level": 1}, headers=H).json()["ok"]
    assert store.tenant(t)["max_auto_level"] == 1 and "windows.flush_dns" in store.tenant(t)["auto_tools"]
    assert c.post(f"/api/tenants/{t}/repair-level", json={"level": 3}, headers=H).status_code == 422  # level 3 impossible
    assert c.post(f"/api/devices/{agent}/revoke", json={}, headers=H).json()["ok"]
    assert store.device(agent)["status"] == "revoked"
