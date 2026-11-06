"""Password vault (user request 06.11.2026): every PC gets its own RustDesk password, set by the agent and
sealed to the owner's vault; only the phone, with the master password, can read it."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from bonelia.agent.agent import Agent, AgentState
from bonelia.security import vault
from bonelia.server.dashboard import create_dashboard_app
from tests.integration.test_agent import FakePC
from tests.integration.test_server_e2e import env, usb  # noqa: F401  (fixture + helper)

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
MASTER = "Ana-Sifre-2026"
RD = {"installed": True, "rustdesk_id": "494159677", "service": "running"}


def panel(store) -> TestClient:
    return TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)


def entries(dash, kind=None):
    return [e for e in dash.get("/api/vault").json()["entries"] if kind is None or e["kind"] == kind]


def test_agent_sets_its_own_password_and_only_the_phone_can_read_it(tmp_path, env):  # noqa: F811
    store = env["store"]
    dash = panel(store)
    s = usb(tmp_path, env, "KASSE-VLT", env["a"], scopes=("diagnose", "repair:windows"))
    pc, set_calls = FakePC(), []
    agent = Agent(s.client, AgentState(tmp_path / "v.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
                  remote=lambda: RD, set_remote_password=lambda pw: set_calls.append(pw) or True)
    agent.cycle()
    assert set_calls == [] and dash.get("/api/vault").json()["meta"] is None  # no vault yet: nothing is touched

    meta = vault.create(MASTER)
    assert dash.post("/api/vault/setup", json={"meta": meta}).status_code == 200
    agent.cycle()  # the reply hands over the vault's public key
    agent.cycle()  # a random password is set in RustDesk, sealed and sent
    assert len(set_calls) == 1 and len(set_calls[0]) == 16
    [e] = entries(dash, "rustdesk")
    assert e["rustdesk_id"] == "494159677" and e["title"] == "KASSE-VLT" and e["customer"] == "Kunde A"
    assert e["device_id"] == s.creds.device_id and e["rotating"] is False
    assert vault.open_box(vault.unlock(meta, MASTER), e["box"])["password"] == set_calls[0]

    # Nothing readable anywhere on the server: not in the database, not in the device status.
    for f in env["cfg"].data_dir.rglob("*"):
        if f.is_file():
            assert set_calls[0].encode() not in f.read_bytes(), f
    assert "box" not in json.loads(store.device(s.creds.device_id)["last_status"])["remote"]

    agent.cycle(); agent.cycle()
    assert len(set_calls) == 1  # once per vault, not every cycle

    # "New password" in the panel: the agent changes it on its next cycles and the vault entry follows.
    assert dash.post(f"/api/vault/rotate/{s.creds.device_id}").status_code == 200
    assert entries(dash, "rustdesk")[0]["rotating"] is True
    agent.cycle(); agent.cycle()
    assert len(set_calls) == 2 and set_calls[1] != set_calls[0]
    [e] = entries(dash, "rustdesk")
    assert e["rotating"] is False and vault.open_box(vault.unlock(meta, MASTER), e["box"])["password"] == set_calls[1]


def test_failed_password_change_is_retried_later_and_old_vault_boxes_are_refused(tmp_path, env):  # noqa: F811
    store = env["store"]
    dash = panel(store)
    meta = vault.create(MASTER)
    dash.post("/api/vault/setup", json={"meta": meta})
    s = usb(tmp_path, env, "KASSE-FAIL", env["a"], scopes=("diagnose", "repair:windows"))
    pc, calls = FakePC(), []
    agent = Agent(s.client, AgentState(tmp_path / "f.json"), executors=pc.executors(), scan=pc.scan, maintenance_tools=(),
                  remote=lambda: RD, set_remote_password=lambda pw: calls.append(pw) and False)
    for _ in range(4):
        agent.cycle()
    assert len(calls) == 1 and entries(dash) == []  # RustDesk refused: not hammered every cycle, nothing stored

    # A box sealed for another (old) vault, or garbage, is not stored.
    other = vault.create("anderes-passwort")
    for sealed in ({"box": vault.seal(other["pub"], {"password": "x"}), "for": vault.fingerprint(other["pub"])},
                   {"box": {"v": 1, "epk": "x", "nonce": "y", "ct": "z"}, "for": vault.fingerprint(meta["pub"])}, "text"):
        reply = s.client.heartbeat({"cycles": 1, "remote": {**RD, "vault": sealed}})
        assert reply.get("vault_saved") is not True
    assert entries(dash) == []


def test_panel_setup_manual_entries_and_reset(tmp_path, env):  # noqa: F811
    store = env["store"]
    dash = panel(store)
    assert dash.post("/api/vault/setup", json={"meta": {"v": 1}}).status_code == 422
    meta = vault.create(MASTER)
    assert dash.post("/api/vault/setup", json={"meta": meta}).status_code == 200
    assert dash.post("/api/vault/setup", json={"meta": vault.create("x" * 12)}).status_code == 409  # never overwritten
    assert dash.get("/api/vault").json()["meta"] == meta

    box = vault.seal(meta["pub"], {"password": "Wlan-Gast-77", "user": "admin", "note": "Fritzbox"})
    r = dash.post("/api/vault/entries", json={"title": "Router", "customer": "Pizzeria Roma", "box": box})
    assert r.status_code == 200
    [e] = entries(dash, "manual")
    assert e["title"] == "Router" and e["customer"] == "Pizzeria Roma" and e["box"] == box
    edited = vault.seal(meta["pub"], {"password": "Neu-99"})
    dash.post("/api/vault/entries", json={"id": e["id"], "title": "Router 2", "customer": "Pizzeria Roma", "box": edited})
    assert [x["title"] for x in entries(dash)] == ["Router 2"]
    assert dash.post("/api/vault/entries", json={"title": "x", "box": {"v": 1}}).status_code == 422
    assert dash.post("/api/vault/entries", json={"title": "", "box": box}).status_code == 422
    assert dash.post(f"/api/vault/entries/{e['id']}/delete").status_code == 200 and entries(dash) == []
    assert dash.post("/api/vault/rotate/nope").status_code == 404

    # Forgotten master password: start over, everything in the vault is gone (it could not be read anyway).
    assert dash.post("/api/vault/reset", json={"confirm": "evet"}).status_code == 422
    assert dash.post("/api/vault/reset", json={"confirm": "SIL"}).status_code == 200
    assert dash.get("/api/vault").json() == {"meta": None, "entries": []}
    acts = [a["action"] for a in store.audit_log(env["a"])] + [a["action"] for a in store.audit_log(None)]
    assert "vault.reset" in acts

    no_token = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999")
    assert no_token.get("/api/vault").status_code == 403
    js = no_token.get("/vault.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"] and "BoneliaVault" in js.text
