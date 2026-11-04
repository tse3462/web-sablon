from fastapi.testclient import TestClient

from bonelia.monitor.portable import PortableHome
from bonelia.monitor.session import Session
from bonelia.monitor.ui import create_ui_app

TOKEN = "t" * 32


def client(tmp_path):
    s = Session(home=PortableHome(tmp_path / "usb").ensure(), lang="tr")
    app = create_ui_app(s, TOKEN, 5555)
    return TestClient(app, base_url="http://127.0.0.1:5555"), s


def test_ui_requires_token_and_local_host(tmp_path):
    c, _ = client(tmp_path)
    assert c.get("/api/status").status_code == 403
    assert c.get("/api/status", headers={"x-ui-token": "wrong"}).status_code == 403
    assert c.get("/api/status", headers={"x-ui-token": TOKEN, "host": "evil.example:5555"}).status_code == 403  # DNS rebinding
    r = c.get("/api/status", headers={"x-ui-token": TOKEN})
    assert r.status_code == 200 and r.json()["enrolled"] is False
    page = c.get("/")
    assert page.status_code == 200 and "BONELİA" in page.text and "frame-ancestors 'none'" in page.headers["content-security-policy"]


def test_ui_scan_and_report_without_enrollment(tmp_path):
    c, s = client(tmp_path)
    h = {"x-ui-token": TOKEN}
    r = c.post("/api/scan", json={"mode": "quick", "analyze": True}, headers=h)
    assert r.status_code == 200
    rep = r.json()["report"]
    assert rep["customer_ref"] == "unregistered" and any("kayıtlı değil" in n for n in rep["notices"])
    assert c.get("/api/report.html", headers=h).status_code == 200
    # nothing is written to the USB without a vault (no plaintext customer data on the stick)
    assert list((s.home.root / "reports").iterdir()) == []
    assert c.post("/api/export", json={"dest": str(s.home.root / "x")}, headers=h).status_code == 400
    ok = c.post("/api/export", json={"dest": str(tmp_path / "desktop")}, headers=h)
    assert ok.status_code == 200 and len(ok.json()["files"]) == 3
    assert c.post("/api/scan", json={"mode": "rm -rf"}, headers=h).status_code == 422
    assert c.post("/api/chat", json={"question": "x"}, headers=h).status_code == 409


def test_language_switch_persists(tmp_path):
    c, s = client(tmp_path)
    assert c.post("/api/language", json={"language": "de"}, headers={"x-ui-token": TOKEN}).status_code == 200
    assert s.home.settings()["language"] == "de" and s.lang == "de"


def test_quit_button_ends_the_program(tmp_path, monkeypatch):
    """The double-click build has no console window, so the UI must be able to close the program."""
    import bonelia.monitor.ui as ui_mod

    exited = []
    monkeypatch.setattr(ui_mod.os, "_exit", lambda code: exited.append(code))
    c, _ = client(tmp_path)
    assert c.post("/api/quit", headers={"x-ui-token": "wrong"}).status_code == 403  # other pages cannot close it
    assert c.post("/api/quit", headers={"x-ui-token": TOKEN}).json() == {"ok": True}
    import time
    time.sleep(0.8)
    assert exited == [0]
