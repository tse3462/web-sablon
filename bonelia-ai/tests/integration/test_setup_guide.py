"""Setup guide (07.11.2026): the panel checks every step against GitHub and writes the repository secrets itself, with
GitHub's encryption; the owner only adds a permission to his GitHub key and runs one SQL in Supabase."""

import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from nacl.public import PrivateKey, SealedBox

from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.repair import TOKEN_KEY
from bonelia.server.setup_guide import health_url, supabase_ref
from bonelia.server.store import Store

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
PAT = "github_pat_" + "A1b2" * 10
REF = "tdsxkmjlzgjriugepdlh"
POOLER = f"postgresql://postgres.{REF}:[YOUR-PASSWORD]@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
PW = "Xy7" * 10


def test_supabase_id_and_monitor_address():
    for text in (REF, f"https://{REF}.supabase.co", f"https://supabase.com/dashboard/project/{REF}/sql/new", f" {REF.upper()} "):
        assert supabase_ref(text) == REF
    assert supabase_ref("https://example.com") is None
    assert health_url(POOLER, PW, REF) == (f"postgresql://bonelia_health_monitor.{REF}:{PW}@aws-0-eu-central-1.pooler.supabase.com"
                                           ":5432/postgres?sslmode=no-verify")  # session mode, monitor role, never the postgres user
    for bad, err in ((POOLER.replace("pooler.supabase.com", "evil.example"), "invalid_pooler"),
                     (POOLER.replace(REF, "a" * 20), "other_project")):
        with pytest.raises(ValueError, match=err):
            health_url(bad, PW, REF)
    with pytest.raises(ValueError, match="invalid_password"):
        health_url(POOLER, "short", REF)


class FakeGitHub:
    def __init__(self, secrets_ok=True):
        self.key = PrivateKey.generate()
        self.secrets, self.secrets_ok = {"OTHER": 1}, secrets_ok
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, req):
        p = req.url.path
        if p.endswith("/actions/workflows"):
            return httpx.Response(200, json={"workflows": [{"path": ".github/workflows/ci.yml"}, {"path": ".github/workflows/db-saglik.yml"},
                                                           {"path": ".github/workflows/auto-repair.yml"}, {"path": ".github/workflows/claude-gelistir.yml"}]})
        if not self.secrets_ok and "/secrets" in p:
            return httpx.Response(403)
        if p.endswith("/actions/secrets"):
            return httpx.Response(200, json={"secrets": [{"name": n} for n in self.secrets]})
        if p.endswith("/actions/secrets/public-key"):
            return httpx.Response(200, json={"key_id": "k1", "key": base64.b64encode(bytes(self.key.public_key)).decode()})
        if req.method == "PUT" and "/actions/secrets/" in p:
            body = json.loads(req.content)
            assert body["key_id"] == "k1"
            self.secrets[p.rsplit("/", 1)[-1]] = SealedBox(self.key).decrypt(base64.b64decode(body["encrypted_value"])).decode()
            return httpx.Response(201)
        return httpx.Response(404)


def panel(tmp_path, monkeypatch, gh):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    store.set_setting("anthropic_api_key", "sk-ant-api03-" + "B" * 40)
    store.set_setting(APPS_KEY, [{"id": "a1", "name": "BNL Rezervasyon", "url": "https://reservierung.bnl-digital.de",
                                  "repair_repo": "tse3462/bonelia-ai-rezervation"}])
    import bonelia.server.autopilot as ap
    import bonelia.server.setup_guide as mod

    monkeypatch.setattr(mod, "TRANSPORT", gh.transport)
    monkeypatch.setattr(ap, "CONNECT", lambda **kw: type("C", (), {"close": lambda self: None})())  # Supabase knows it
    return store, TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)


def test_guide_checks_steps_and_writes_the_secrets_itself(tmp_path, monkeypatch):
    gh = FakeGitHub()
    store, c = panel(tmp_path, monkeypatch, gh)
    s = c.get("/api/setup/a1").json()
    assert s["token"] and s["actions"] == "ok" and all(s["workflows"].values()) and s["secrets_access"] == "ok"
    assert s["secrets"] == {"ANTHROPIC_API_KEY": False, "DB_HEALTH_URL": False} and s["brain_key"] and s["supabase_ref"] is None
    assert c.post("/api/setup/a1/supabase", json={"value": f"https://{REF}.supabase.co"}).json()["supabase_ref"] == REF
    assert c.post("/api/setup/a1/anthropic", json={}).json()["secrets"]["ANTHROPIC_API_KEY"] is True
    assert gh.secrets["ANTHROPIC_API_KEY"].startswith("sk-ant-api03-")  # GitHub got exactly the brain's key, encrypted
    r = c.post("/api/setup/a1/dburl", json={"pooler": POOLER, "password": PW})
    assert r.status_code == 200 and r.json()["secrets"]["DB_HEALTH_URL"] is True
    assert gh.secrets["DB_HEALTH_URL"].startswith(f"postgresql://bonelia_health_monitor.{REF}:")
    assert PW not in json.dumps(store.get_setting("apps")) and PW not in r.text  # never in the app list or an answer
    # kept only as the read-only monitor address for the free five-minute check (autopilot, 07.11.2026)
    assert store.get_setting("db_monitor_urls")["a1"] == gh.secrets["DB_HEALTH_URL"]
    assert c.post("/api/setup/a1/dburl", json={"pooler": "postgresql://x", "password": PW}).status_code == 422
    assert c.get("/api/setup/nope").status_code == 404
    html = c.get("/").text
    assert 'id="setupBox"' in html and "function setupLoad(" in html and "crypto.getRandomValues" in html
    # 07.11.2026: Safari reloaded the tab while the owner was in Supabase, the password was lost and a second one went
    # to GitHub ("password authentication failed"). The password now survives a reload, and steps 4-5 can be redone.
    assert "sessionStorage" in html and "function suPwSet(" in html
    for key in ("su_title", "su_token", "su_jobs", "su_sql", "su_pooler", "su_claude", "su_try", "su_perm_help",
                "su_redo", "su_regen_q", "dbh_failed_help"):
        assert html.count(key + ":") == 2


def test_a_program_without_a_repository_is_linked_in_the_guide(tmp_path, monkeypatch):
    """Owner's screenshot 07.11.2026: the guide was empty ("Seçenek Yok") because no program had a repository yet."""
    gh = FakeGitHub()
    store, c = panel(tmp_path, monkeypatch, gh)
    store.set_setting(APPS_KEY, [{"id": "r1", "name": "Rezervasyon", "url": "https://reservierung.bnl-digital.de"},
                                 {"id": "s1", "name": "Site", "url": "https://bnl-digital.de"}])
    g = c.get("/api/setup").json()
    assert g["linked"] == [] and [(u["id"], u["suggest"]) for u in g["unlinked"]] == [
        ("r1", "tse3462/bonelia-ai-rezervation"), ("s1", None)]  # the known repository is offered, nothing is guessed
    r = c.post("/api/setup/link", json={"app_id": "r1", "repo": "tse3462/bonelia-ai-rezervation"})
    assert r.status_code == 200 and [p["id"] for p in r.json()["linked"]] == ["r1"]
    assert store.get_setting(APPS_KEY)[0]["repair_repo"] == "tse3462/bonelia-ai-rezervation"
    assert c.get("/api/setup/r1").json()["repo"] == "tse3462/bonelia-ai-rezervation"
    assert c.post("/api/setup/link", json={"app_id": "s1", "repo": "not a repo"}).status_code == 422
    assert c.post("/api/setup/link", json={"app_id": "nope", "repo": "a/b"}).status_code == 404
    html = c.get("/").text
    assert 'id="suLink"' in html and html.count("su_link:") == 2 and html.count("su_link_help:") == 2


def test_a_password_supabase_does_not_know_never_reaches_github(tmp_path, monkeypatch):
    """07.11.2026: twice the SQL was not run with the password that went to GitHub; now BONELIA tries it first."""
    gh = FakeGitHub()
    store, c = panel(tmp_path, monkeypatch, gh)
    import bonelia.server.autopilot as ap

    def refuse(**kw):
        raise Exception({"S": "FATAL", "C": "28P01", "M": 'password authentication failed for user "bonelia_health_monitor"'})
    monkeypatch.setattr(ap, "CONNECT", refuse)
    c.post("/api/setup/a1/supabase", json={"value": REF})
    r = c.post("/api/setup/a1/dburl", json={"pooler": POOLER, "password": PW})
    assert r.status_code == 422 and r.json()["detail"] == "db_password_mismatch" and "DB_HEALTH_URL" not in gh.secrets
    assert ap.db_login("postgresql://u.x:p@h:5432/postgres", lambda **kw: (_ for _ in ()).throw(OSError("timed out"))) == "unreachable"
    html = c.get("/").text
    assert html.count("db_password_mismatch:") == 2 and html.count("ap_db_fail:") == 2


def test_missing_secret_permission_is_named(tmp_path, monkeypatch):
    gh = FakeGitHub(secrets_ok=False)
    store, c = panel(tmp_path, monkeypatch, gh)
    assert c.get("/api/setup/a1").json()["secrets_access"] == "denied"
    assert c.post("/api/setup/a1/anthropic", json={}).status_code == 409
