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


def test_delete_device_removes_it_from_the_list(tmp_path):
    store, c, t, usb, agent = setup(tmp_path)
    assert c.post(f"/api/devices/{usb}/delete", json={}, headers=H).json()["ok"]  # clean up an old test entry
    assert store.device(usb) is None  # gone for good
    assert all(d["id"] != usb for d in store.devices())
    assert store.device(agent) is not None  # the working PC is untouched
    assert c.post(f"/api/devices/{usb}/delete", json={}, headers=H).status_code == 404  # already gone
    assert "device.deleted" in [a["action"] for a in store.audit_log(t)]  # recorded in the audit log


def test_remote_host_allowlist_and_bind_safety(tmp_path):
    from bonelia.server.dashboard import create_dashboard_app, is_safe_bind

    # only loopback and Tailscale (100.64/10) addresses may host the panel
    assert is_safe_bind("127.0.0.1") and is_safe_bind("100.101.102.103") and is_safe_bind("foo.ts.net")
    assert not is_safe_bind("192.168.1.5") and not is_safe_bind("0.0.0.0") and not is_safe_bind("8.8.8.8")

    store = Store(tmp_path / "db.sqlite")
    store.create_tenant("T")
    c = TestClient(create_dashboard_app(store, TOKEN, 8742, extra_hosts=["100.101.102.103"]),
                   base_url="http://100.101.102.103:8742")
    # the phone (via Tailscale) reaches it with the right Host + token
    assert c.get("/api/overview", headers={"x-ui-token": TOKEN, "host": "100.101.102.103:8742"}).status_code == 200
    # a wrong Host (e.g. DNS rebinding or a public name) is refused
    assert c.get("/api/overview", headers={"x-ui-token": TOKEN, "host": "evil.example:8742"}).status_code == 403
    # token still required
    assert c.get("/api/overview", headers={"host": "100.101.102.103:8742"}).status_code == 403


def test_stable_token_persists(tmp_path):
    from bonelia.server.dashboard import _stable_token

    t1 = _stable_token(tmp_path)
    assert t1 and _stable_token(tmp_path) == t1


def test_tailscale_ipv4_parsing(monkeypatch):
    import subprocess

    from bonelia.server import dashboard as d

    class R:
        def __init__(self, out):
            self.stdout = out

    monkeypatch.setattr(d.shutil if hasattr(d, "shutil") else __import__("shutil"), "which", lambda x: "tailscale", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R("fe80::1\n100.68.212.97\n"))
    assert d.tailscale_ipv4() == "100.68.212.97"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R("192.168.1.5\n"))
    assert d.tailscale_ipv4() is None
    def boom(*a, **k):
        raise OSError("not installed")
    monkeypatch.setattr(subprocess, "run", boom)
    assert d.tailscale_ipv4() is None


def test_serve_dashboard_host_auto_falls_back_without_tailscale(tmp_path, monkeypatch):
    import bonelia.server.dashboard as d

    captured = {}
    monkeypatch.setattr(d, "tailscale_ipv4", lambda: None)
    monkeypatch.setattr(d, "create_dashboard_app", lambda *a, **k: object())

    class FakeUvicorn:
        def run(self, app, host, port, log_level):
            captured["host"] = host

    import sys
    monkeypatch.setitem(sys.modules, "uvicorn", FakeUvicorn())
    store = Store(tmp_path / "db")
    assert d.serve_dashboard(store, port=8751, open_browser=False, host="auto", data_dir=tmp_path) == 0
    assert captured["host"] == "127.0.0.1"  # no Tailscale -> local, not a crash


def test_serve_dashboard_host_auto_uses_detected_tailscale(tmp_path, monkeypatch):
    import sys

    import bonelia.server.dashboard as d

    captured = {}
    monkeypatch.setattr(d, "tailscale_ipv4", lambda: "100.68.212.97")
    monkeypatch.setattr(d, "create_dashboard_app", lambda *a, **k: object())
    monkeypatch.setitem(sys.modules, "uvicorn", type("U", (), {"run": staticmethod(lambda app, host, port, log_level: captured.update(host=host))})())
    store = Store(tmp_path / "db")
    assert d.serve_dashboard(store, port=8751, open_browser=False, host="auto", data_dir=tmp_path) == 0
    assert captured["host"] == "100.68.212.97"
    assert (tmp_path / "panel-url.txt").read_text(encoding="utf-8").count("100.68.212.97:8751") == 1


def test_backup_policy_is_set_per_pc_and_validated(tmp_path):
    store, c, t, usb, agent = setup(tmp_path)
    r = c.post(f"/api/devices/{agent}/backup-policy", json={"paths": ["D:\\Kasa\\Yedek", " \\\\NAS\\yedek "], "max_age_days": 3}, headers=H)
    assert r.json()["backup"] == {"paths": ["D:\\Kasa\\Yedek", "\\\\NAS\\yedek"], "max_age_days": 3}
    dev = next(d for d in c.get("/api/overview", headers=H).json()["devices"] if d["id"] == agent)
    assert dev["backup"]["paths"] == ["D:\\Kasa\\Yedek", "\\\\NAS\\yedek"]
    for bad in (["Yedek"], ["/etc"], ["D:\\a|b"], ["C:"]):
        assert c.post(f"/api/devices/{agent}/backup-policy", json={"paths": bad}, headers=H).status_code == 422
    assert c.post(f"/api/devices/{agent}/backup-policy", json={"paths": ["D:\\X"], "max_age_days": 0}, headers=H).status_code == 422
    assert c.post(f"/api/devices/{agent}/backup-policy", json={"paths": []}, headers=H).json()["backup"] is None  # cleared
    assert store.device_policy(agent) == {}
    assert c.post("/api/devices/nope/backup-policy", json={"paths": []}, headers=H).status_code == 404


class FakeTelegram:
    """Stands in for api.telegram.org (no network)."""

    TOKEN = "123456789:" + "A" * 35

    def __init__(self):
        self.sent: list[tuple[str, str]] = []
        self.messages: list[dict] = []

    def handler(self, request):
        import json as _json

        import httpx

        path = request.url.path
        if f"/bot{self.TOKEN}/" not in path:
            return httpx.Response(401, json={"ok": False, "description": "Unauthorized"})
        method = path.rsplit("/", 1)[-1]
        body = _json.loads(request.content or b"{}")
        if method == "getMe":
            return httpx.Response(200, json={"ok": True, "result": {"username": "bonelia_test_bot"}})
        if method == "getUpdates":
            return httpx.Response(200, json={"ok": True, "result": [{"update_id": i, "message": m} for i, m in enumerate(self.messages)]})
        if method == "sendMessage":
            self.sent.append((str(body["chat_id"]), body["text"]))
            return httpx.Response(200, json={"ok": True, "result": {}})
        return httpx.Response(404, json={"ok": False})


def test_telegram_is_connected_entirely_from_the_panel(tmp_path):
    import httpx

    from bonelia.server.notify import TelegramAPI, build_notifier

    store = Store(tmp_path / "db.sqlite")
    fake = FakeTelegram()
    api = TelegramAPI(transport=httpx.MockTransport(fake.handler))
    c = TestClient(create_dashboard_app(store, TOKEN, 9999, telegram_api=api), base_url="http://127.0.0.1:9999")
    assert c.get("/api/settings/telegram", headers=H).json()["state"] == "off"
    assert c.post("/api/settings/telegram/token", json={"token": "hello"}, headers=H).status_code == 422  # not a token
    assert c.post("/api/settings/telegram/token", json={"token": "123456789:" + "B" * 35}, headers=H).json()["detail"] == "token_rejected"
    r = c.post("/api/settings/telegram/token", json={"token": " " + fake.TOKEN + " "}, headers=H).json()
    assert r == {"state": "pending", "bot": "bonelia_test_bot", "chat_name": None}
    assert fake.TOKEN not in c.get("/api/settings/telegram", headers=H).text  # the token is never sent back
    assert c.post("/api/settings/telegram/connect", headers=H).json()["detail"] == "no_message"  # owner has not written yet
    fake.messages.append({"chat": {"id": 4242, "type": "private", "first_name": "Bonelia"}, "text": "/start"})
    r = c.post("/api/settings/telegram/connect", headers=H).json()
    assert r["state"] == "on" and r["chat_name"] == "Bonelia"
    assert fake.sent[-1][0] == "4242" and "bildirimler" in fake.sent[-1][1]
    assert c.post("/api/settings/telegram/test", headers=H).json()["ok"] and len(fake.sent) == 2
    # the server's notifier uses it at once (no restart, no env var)
    n = build_notifier(store, {"windows_toast": False})
    n.channels[0].api = api
    assert n.check_offline() == [] and n.test() and len(fake.sent) == 3
    assert c.post("/api/settings/telegram/off", headers=H).json()["state"] == "off"
    assert not n.test()  # switched off
    actions = [a["action"] for a in store.audit_log()]
    assert {"settings.telegram_token", "settings.telegram_on", "settings.telegram_off"} <= set(actions)


def test_inactive_telegram_does_not_swallow_notifications(tmp_path):
    from bonelia.server.notify import build_notifier

    store = Store(tmp_path / "db.sqlite")
    n = build_notifier(store, {"windows_toast": False})  # Telegram not connected, no other channel
    assert n._send("k1", timedelta(hours=1), "t", "b") is False
    assert store.notification_due("k1", timedelta(hours=1))  # still due: will be sent once a channel exists


def test_my_apps_launcher_add_edit_move_delete(tmp_path):
    store, c, *_ = setup(tmp_path)
    assert c.get("/api/apps", headers=H).json() == {"apps": []}
    a = c.post("/api/apps", json={"name": "VeedelKorb Admin", "url": "https://admin.veedelkorb.de", "icon": "🛒"}, headers=H).json()["apps"]
    b = c.post("/api/apps", json={"name": "Kasa", "url": "http://192.168.1.20:8080/admin"}, headers=H).json()["apps"]
    assert [x["name"] for x in b] == ["VeedelKorb Admin", "Kasa"] and b[1]["icon"] == "🔗"
    for bad in ("javascript:alert(1)", "ftp://x.de/abc", "https://a b.de", 'https://x.de/"><script>'):
        assert c.post("/api/apps", json={"name": "x", "url": bad}, headers=H).status_code == 422
    first = a[0]["id"]
    edited = c.post("/api/apps", json={"id": first, "name": "VK Admin", "url": "https://admin.veedelkorb.de/login", "icon": "🍦"}, headers=H).json()["apps"]
    assert edited[0] == {"id": first, "name": "VK Admin", "url": "https://admin.veedelkorb.de/login", "icon": "🍦"}
    assert c.post("/api/apps", json={"id": "nope", "name": "x", "url": "https://x.de"}, headers=H).status_code == 404
    moved = c.post(f"/api/apps/{first}/move?step=1", json={}, headers=H).json()["apps"]
    assert [x["name"] for x in moved] == ["Kasa", "VK Admin"]
    left = c.post(f"/api/apps/{first}/delete", json={}, headers=H).json()["apps"]
    assert [x["name"] for x in left] == ["Kasa"]
    assert "password" not in str(store.get_setting("apps")).lower()  # addresses only, never credentials
    actions = [x["action"] for x in store.audit_log()]
    assert "settings.app_saved" in actions and "settings.app_deleted" in actions
    assert c.get("/api/apps").status_code == 403  # token required like every other panel API


def test_token_is_found_in_whatever_the_phone_pastes():
    from bonelia.server.notify import extract_token

    tok = "7234567890:AAHkx9Q2mPz7Lw3R5tYbV8nC1dE4fG6hJk0"
    assert extract_token(tok) == tok
    assert extract_token(f"⁨{tok}⁩​") == tok  # invisible marks added when copying on a phone
    assert extract_token(f" {tok}\n") == tok
    assert extract_token(tok.replace(":", "：")) == tok  # full-width colon
    botfather = ("Done! Congratulations on your new bot. You will find it at t.me/bonelia_bildirim_bot. ...\n\n"
                 f"Use this token to access the HTTP API:\n{tok}\nKeep your token secure and store it safely, ...\n"
                 "For a description of the Bot API, see this page: https://core.telegram.org/bots/api")
    assert extract_token(botfather) == tok  # the whole @BotFather message works too
    assert extract_token("7234567890") is None  # only the number in front is not a token
    assert extract_token("AAHkx9Q2mPz7Lw3R5tYbV8nC1dE4fG6hJk0") is None
    assert extract_token("") is None


def test_home_has_the_live_center_built_from_real_data(tmp_path):
    """Dark animated live center on the home page (user request 06.11.2026): PCs as a network around the AI,
    repairs by kind and result, telemetry and agent skills -- all from /api/overview, findings and repairs."""
    _, c, *_ = setup(tmp_path)
    html = c.get("/").text
    assert '<section class="live" id="live"' in html and "function renderLive(" in html
    assert "renderLive(o,f,r)" in html  # filled from the same data as the rest of the home page
    assert "prefers-reduced-motion" in html  # motion stops for people who turned it off
    for key in ("lv_title", "lv_repairs_kind", "lv_skills", "lv_activity"):
        assert html.count(key + ":") == 2  # Turkish and German text


def test_panel_icons_for_tab_and_phone_home_screen(tmp_path):
    """BNL digital mark (06.11.2026) as tab and iPhone home-screen icon; served without the token so the phone
    can fetch it, but still only on the panel's own host."""
    _, c, *_ = setup(tmp_path)
    for path, kind in (("/favicon.ico", "image/x-icon"), ("/apple-touch-icon.png", "image/png"), ("/icon.svg", "image/svg+xml")):
        r = c.get(path)
        assert r.status_code == 200 and r.headers["content-type"].startswith(kind), path
    assert c.get("/apple-touch-icon.png").content[1:4] == b"PNG"
    assert c.get("/favicon.ico", headers={"host": "evil.example:9999"}).status_code == 403
    html = c.get("/").text
    assert '<link rel="apple-touch-icon" href="/apple-touch-icon.png">' in html and 'href="/icon.svg"' in html
