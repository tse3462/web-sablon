from fastapi.testclient import TestClient

from bonelia.recovery.ui import create_recovery_app

TOKEN = "r" * 32


def client():
    return TestClient(create_recovery_app(TOKEN, 5566, "tr"), base_url="http://127.0.0.1:5566")


def test_local_only_and_token_and_pages():
    c = client()
    assert c.get("/api/status").status_code == 403
    assert c.get("/api/status", headers={"x-ui-token": TOKEN, "host": "evil:5566"}).status_code == 403
    s = c.get("/api/status", headers={"x-ui-token": TOKEN}).json()
    assert "is_admin" in s and s["bootrec_guide"]
    assert "Kurtarma" in c.get("/").text


def test_unknown_op_and_readonly_without_admin(monkeypatch):
    import bonelia.recovery.ui as ui

    monkeypatch.setattr(ui, "is_admin", lambda: False)
    c = client()
    assert c.post("/api/op/nope", json={"params": {}}, headers={"x-ui-token": TOKEN}).status_code == 404
    # repair needs admin
    assert c.post("/api/op/sfc", json={"params": {}}, headers={"x-ui-token": TOKEN}).status_code == 403
    # read-only inspection is allowed (returns not_windows off Windows, but not blocked)
    r = c.post("/api/op/restore_points", json={"params": {}}, headers={"x-ui-token": TOKEN})
    assert r.status_code == 200
