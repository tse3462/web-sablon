"""Weekly database check of the own programs (07.11.2026): BONELIA picks up each new report of the GitHub job
"db-saglik", keeps the latest one per program for the panel and sends it to Telegram once."""

import io
import json
import zipfile

import httpx
from fastapi.testclient import TestClient

from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.db_health import DbHealthWatch
from bonelia.server.repair import TOKEN_KEY, GitHubRepair
from bonelia.server.store import Store

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
PAT = "github_pat_" + "A1b2" * 10
REPORT = {"status": "warn", "db_mb": 18.4, "summary": "Veritabanı 18 MB, sağlıklı. Bir tabloda temizlik gecikmiş.",
          "findings": [{"level": "warn", "code": "dead_rows", "text": "ai_reservation.guests: 50000 silinmiş satır temizlenmemiş."},
                       {"level": "bad", "code": "x", "text": "ignored"}], "run_url": "https://github.com/run/71"}


def zipped(rep):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", json.dumps(rep))
    return buf.getvalue()


class FakeGitHub:
    def __init__(self):
        self.run_id, self.dispatched, self.has_job = 71, [], True
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, req):
        p = req.url.path
        if p.endswith("/actions/workflows/db-saglik.yml/runs"):
            if not self.has_job:
                return httpx.Response(404)
            return httpx.Response(200, json={"workflow_runs": [{"id": self.run_id, "status": "completed", "updated_at": "2026-11-09T05:20:00Z",
                                                                "html_url": f"https://github.com/run/{self.run_id}"}, {"id": 3, "status": "completed"}]})
        if p.endswith(f"/actions/runs/{self.run_id}/artifacts"):
            return httpx.Response(200, json={"artifacts": [{"name": "db-saglik-report", "expired": False,
                                                            "archive_download_url": "https://api.github.com/zip/1"}]})
        if p == "/zip/1":
            return httpx.Response(200, content=zipped(REPORT))
        if req.method == "POST" and p.endswith("/actions/workflows/db-saglik.yml/dispatches"):
            self.dispatched.append(json.loads(req.content))
            return httpx.Response(204)
        return httpx.Response(404)


class Sent:
    def __init__(self):
        self.messages = []

    def db_health(self, name, rep):
        self.messages.append((name, rep["status"], rep["summary"]))


def setup(tmp_path, gh=None):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    store.set_setting(APPS_KEY, [{"id": "a1", "name": "BNL Rezervasyon", "url": "https://reservierung.bnl-digital.de",
                                  "repair_repo": "tse3462/bonelia-ai-rezervation"},
                                 {"id": "a2", "name": "Site", "url": "https://bnl-digital.de"}])
    gh = gh or FakeGitHub()
    sent = Sent()
    return store, gh, sent, DbHealthWatch(store, GitHubRepair(store, gh.transport), sent)


def test_a_new_weekly_report_is_kept_and_sent_once(tmp_path):
    store, gh, sent, w = setup(tmp_path)
    assert w.poll() == ["a1"]
    rep = w.reports()["a1"]
    assert rep["status"] == "warn" and rep["db_mb"] == 18.4 and rep["run_id"] == 71 and rep["name"] == "BNL Rezervasyon"
    assert [f["code"] for f in rep["findings"]] == ["dead_rows"]  # unknown levels are dropped
    assert sent.messages == [("BNL Rezervasyon", "warn", REPORT["summary"])]
    assert w.poll() == [] and len(sent.messages) == 1  # same run: nothing again
    gh.run_id = 72
    assert w.poll() == ["a1"] and len(sent.messages) == 2


def test_programs_without_the_job_or_without_a_key_are_skipped(tmp_path):
    gh = FakeGitHub()
    gh.has_job = False
    store, gh, sent, w = setup(tmp_path, gh)
    assert w.poll() == [] and sent.messages == []
    store.set_setting(TOKEN_KEY, None)
    assert w.poll() == []


def test_check_now_from_the_panel(tmp_path, monkeypatch):
    store, gh, sent, w = setup(tmp_path)
    import bonelia.server.db_health as mod

    monkeypatch.setattr(mod, "TRANSPORT", gh.transport)
    c = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    g = c.get("/api/dbhealth").json()
    assert [p["id"] for p in g["programs"]] == ["a1"] and g["reports"] == {}
    assert c.post("/api/dbhealth/a1/run", json={}).json()["result"] == "started" and gh.dispatched[0]["ref"] == "main"
    assert c.post("/api/dbhealth/a2/run", json={}).status_code == 404
    w.poll()
    assert c.get("/api/dbhealth").json()["reports"]["a1"]["status"] == "warn"
    html = c.get("/").text
    assert 'id="dbhList"' in html and "function dbhLoad(" in html
    for key in ("dbh_title", "dbh_help", "dbh_now", "dbh_ok", "dbh_warn", "dbh_crit", "dbh_none", "dbh_no_secret"):
        assert html.count(key + ":") == 2
