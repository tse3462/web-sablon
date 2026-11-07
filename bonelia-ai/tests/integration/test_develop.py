"""The "Geliştir" box (user request 07.11.2026): the owner writes (or dictates) a wish in the panel, Claude makes it in
the program's GitHub repository on its own branch with the tests run, the result comes to the panel and Telegram, and
only the owner's "Onayla" takes it into the program."""

import io
import json
import zipfile

import httpx
from fastapi.testclient import TestClient

from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.develop import BONELIA_TARGET, DevelopDesk, GitHubDevelop
from bonelia.server.repair import TOKEN_KEY
from bonelia.server.store import Store

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
PAT = "github_pat_" + "A1b2" * 10


def report_zip(report: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", json.dumps(report))
    return buf.getvalue()


class FakeGitHub:
    def __init__(self):
        self.dispatched, self.merged = [], []
        self.status = "in_progress"
        self.report = {"status": "ready", "summary": "Müşteriler artık alfabetik sıralı. 2 test eklendi, hepsi geçti.",
                       "branch": "claude/gelistir-55", "tests": "passed", "run_url": "https://github.com/tse3462/web-sablon/actions/runs/55"}
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if req.method == "POST" and p.endswith("/actions/workflows/claude-gelistir.yml/dispatches"):
            self.dispatched.append(json.loads(req.content))
            return httpx.Response(204)
        if p.endswith("/actions/workflows/claude-gelistir.yml/runs"):
            rid = self.dispatched[-1]["inputs"]["request_id"] if self.dispatched else "x"
            return httpx.Response(200, json={"workflow_runs": [{"id": 55, "display_title": f"Gelistir {rid}", "status": self.status,
                                                                "conclusion": "success", "html_url": "https://github.com/run/55"}]})
        if p.endswith("/actions/runs/55/artifacts"):
            return httpx.Response(200, json={"artifacts": [{"name": "gelistir-report", "expired": False,
                                                            "archive_download_url": "https://api.github.com/zip/55"}]})
        if p == "/zip/55":
            return httpx.Response(200, content=report_zip(self.report))
        if req.method == "POST" and p.endswith("/merges"):
            self.merged.append(json.loads(req.content))
            return httpx.Response(201, json={"sha": "abc"})
        return httpx.Response(404)


class Sent:
    def __init__(self):
        self.messages = []

    def develop_result(self, target, req):
        self.messages.append((target, req["state"], (req.get("report") or {}).get("summary")))


def desk(tmp_path, gh=None):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    gh = gh or FakeGitHub()
    sent = Sent()
    return store, gh, sent, DevelopDesk(store, GitHubDevelop(store, gh.transport), sent)


def test_a_wish_runs_on_its_own_branch_and_comes_back_with_tests(tmp_path):
    store, gh, sent, d = desk(tmp_path)
    req = d.submit(BONELIA_TARGET["id"], "Panelde müşterileri alfabetik sırala")
    assert req["state"] == "running"
    sent_inputs = gh.dispatched[0]
    assert sent_inputs["ref"] == "claude/bonelia-ai-architecture-z57jp0"  # BONELIA AI's own working branch
    assert sent_inputs["inputs"]["request"] == "Panelde müşterileri alfabetik sırala" and sent_inputs["inputs"]["request_id"] == req["id"]
    d.poll()
    assert d.requests()[0]["state"] == "running" and sent.messages == []
    gh.status = "completed"
    d.poll()
    r = d.requests()[0]
    assert r["state"] == "ready" and r["report"]["branch"] == "claude/gelistir-55" and r["report"]["tests"] == "passed"
    assert sent.messages == [("BONELIA AI", "ready", "Müşteriler artık alfabetik sıralı. 2 test eklendi, hepsi geçti.")]
    d.poll()
    assert len(sent.messages) == 1  # told once


def test_only_the_owners_approval_takes_it_in_and_only_a_ready_tested_result(tmp_path):
    store, gh, sent, d = desk(tmp_path)
    req = d.submit(BONELIA_TARGET["id"], "x ekle")
    assert d.approve(req["id"]) == "not_ready"
    gh.status = "completed"
    d.poll()
    assert d.approve(req["id"]) == "merged"
    assert gh.merged == [{"base": "claude/bonelia-ai-architecture-z57jp0", "head": "claude/gelistir-55",
                          "commit_message": "Geliştir: x ekle (onaylandı)"}]
    assert d.requests()[0]["state"] == "merged" and d.approve(req["id"]) == "not_ready"
    gh2 = FakeGitHub()
    gh2.report = {**gh2.report, "status": "tests_failed", "tests": "failed"}
    gh2.status = "completed"
    _, _, _, d2 = desk(tmp_path / "b", gh2) if (tmp_path / "b").mkdir() is None else (None,) * 4
    r2 = d2.submit(BONELIA_TARGET["id"], "y")
    d2.poll()
    assert d2.requests()[0]["state"] == "tests_failed" and d2.approve(r2["id"]) == "not_ready"


def test_refusals_and_limits(tmp_path):
    store, gh, sent, d = desk(tmp_path)
    for bad in ("", "a" * 2001):
        assert d.submit(BONELIA_TARGET["id"], bad) == "invalid_request"
    assert d.submit("unknown-app", "x") == "unknown_target"
    store.set_setting(TOKEN_KEY, None)
    assert d.submit(BONELIA_TARGET["id"], "x") == "no_token"
    assert gh.dispatched == []


def test_panel_box_targets_and_requests(tmp_path, monkeypatch):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    store.set_setting(APPS_KEY, [{"id": "a1", "name": "BNL Rezervasyon", "url": "https://reservierung.bnl-digital.de",
                                  "icon": "📅", "repair_repo": "tse3462/bonelia-ai-rezervation"}])
    gh = FakeGitHub()
    import bonelia.server.develop as dev

    monkeypatch.setattr(dev, "TRANSPORT", gh.transport)
    c = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999", headers=H)
    g = c.get("/api/develop").json()
    assert [t["name"] for t in g["targets"]] == ["BONELIA AI", "BNL Rezervasyon"] and g["ready"] is True
    assert g["targets"][1]["base"] == "main" and g["targets"][1]["live"] is True  # taking it in = going live there
    r = c.post("/api/develop", json={"target": "a1", "request": "Rezervasyon formuna not alanı ekle"})
    assert r.status_code == 200 and gh.dispatched[0]["ref"] == "main"
    assert c.post("/api/develop", json={"target": "a1", "request": ""}).status_code == 422
    rid = r.json()["requests"][0]["id"]
    assert c.post(f"/api/develop/{rid}/approve", json={}).status_code == 409  # still running
    html = c.get("/").text
    assert 'id="devText"' in html and "function devLoad(" in html
    for key in ("dv_title", "dv_help", "dv_send", "dv_ready", "dv_approve", "dv_live_q", "dv_running"):
        assert html.count(key + ":") == 2
