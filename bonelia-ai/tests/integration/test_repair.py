"""AI repair of an own program (user request 06.11.2026): the alarm starts the GitHub job "Auto repair",
the result comes back to Telegram. Going live stays the owner's decision."""

import io
import json
import zipfile
from datetime import timedelta

import httpx
from fastapi.testclient import TestClient

from bonelia.contracts import utcnow
from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.repair import TOKEN_KEY, GitHubRepair
from bonelia.server.store import Store
from bonelia.server.uptime import UptimeMonitor

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}
PAT = "github_pat_" + "A1b2" * 10
API = "https://api.github.com/repos/o/res/actions"


class Sent:
    def __init__(self):
        self.messages = []

    def uptime_down(self, app_id, name, reason, links=None, repair=False):
        self.messages.append(("down", name, reason, repair))

    def uptime_up(self, app_id, name, minutes):
        self.messages.append(("up", name, minutes))

    def repair_result(self, app_id, name, request_id, report):
        self.messages.append(("repair", name, report))

    def internet_back(self, minutes):
        self.messages.append(("internet", minutes))

    def ssl_expiring(self, app_id, name, days):
        pass


def report_zip(report: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", json.dumps(report))
        z.writestr("claude-log.txt", "…")
    return buf.getvalue()


class FakeGitHub:
    def __init__(self):
        self.site = (503, "down")
        self.dispatched: list[dict] = []
        self.run_status = "in_progress"
        self.report = {"status": "fixed", "cause": "code", "summary": "Son değişiklik /health'i bozmuştu; geri alındı.",
                       "branch": "claude/auto-repair-77", "run_url": "https://github.com/o/res/actions/runs/77"}
        self.blob_auth = "unset"
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("https://res.test/"):
            return httpx.Response(self.site[0], text=self.site[1])
        if url == "https://probe.test/":
            return httpx.Response(204)
        if url.startswith("https://blob.test/"):
            self.blob_auth = request.headers.get("authorization")
            return httpx.Response(200, content=report_zip(self.report))
        assert request.headers["authorization"] == f"Bearer {PAT}"
        if request.method == "POST" and url == f"{API}/workflows/auto-repair.yml/dispatches":
            body = json.loads(request.content)
            self.dispatched.append(body)
            return httpx.Response(204)
        if url.startswith(f"{API}/workflows/auto-repair.yml/runs"):
            runs = [{"id": 5, "display_title": "Auto repair someone-else", "status": "completed", "conclusion": "success",
                     "html_url": "https://github.com/o/res/actions/runs/5"}]
            for i, d in enumerate(self.dispatched):
                runs.append({"id": 77 + i, "display_title": f"Auto repair {d['inputs']['request_id']}", "status": self.run_status,
                             "conclusion": "success" if self.run_status == "completed" else None,
                             "html_url": f"https://github.com/o/res/actions/runs/{77 + i}"})
            return httpx.Response(200, json={"workflow_runs": runs})
        if url == f"{API}/runs/77/artifacts":
            return httpx.Response(200, json={"artifacts": [{"name": "auto-repair-report", "expired": False,
                                                            "archive_download_url": f"{API}/artifacts/9/zip"}]})
        if url == f"{API}/artifacts/9/zip":
            return httpx.Response(302, headers={"location": "https://blob.test/a.zip?sig=x"})
        return httpx.Response(404, json={"message": "Not Found"})


def setup(tmp_path, token=True):
    store = Store(tmp_path / "db.sqlite")
    gh = FakeGitHub()
    c = TestClient(create_dashboard_app(store, TOKEN, 9999, http_transport=gh.transport), base_url="http://127.0.0.1:9999")
    body = {"name": "Reservierung", "url": "https://res.test/", "repair_repo": "o/res"}
    if token:
        body["repair_token"] = PAT
    saved = c.post("/api/apps", headers=H, json=body).json()["apps"][0]
    store.set_setting("autopilot", {"off": [saved["id"]]})  # these tests: the owner turned the autopilot off
    sent, now = Sent(), [utcnow()]
    mon = UptimeMonitor(store, sent, transport=gh.transport, clock=lambda: now[0], ssl_days=lambda h: 90,
                        probes=("https://probe.test/",))
    return store, c, saved, gh, sent, now, mon


def tick(mon, now, n=1):
    for _ in range(n):
        mon.run_once()
        now[0] += timedelta(minutes=1)


def test_alarm_starts_the_ai_once_and_its_result_reaches_telegram(tmp_path):
    store, c, saved, gh, sent, now, mon = setup(tmp_path)
    assert saved["repair_repo"] == "o/res" and "repair_token" not in saved
    assert store.get_setting(TOKEN_KEY) == PAT
    # The key never leaves BONELIA again.
    for path in ("/api/apps", "/api/uptime"):
        assert PAT not in c.get(path, headers=H).text
    assert c.get("/api/uptime", headers=H).json()["repair_ready"] is True

    tick(mon, now, 2)
    assert sent.messages == [("down", "Reservierung", "http_503", True)]
    assert len(gh.dispatched) == 1
    assert gh.dispatched[0]["ref"] == "main" and gh.dispatched[0]["inputs"]["reason"] == "http_503"
    rid = gh.dispatched[0]["inputs"]["request_id"]
    assert len(rid) >= 8

    tick(mon, now, 3)  # still down, job still running: no second job, no result yet
    assert len(gh.dispatched) == 1 and len(sent.messages) == 1
    assert c.get("/api/uptime", headers=H).json()["apps"][0]["repair"]["state"] == "running"

    gh.run_status = "completed"
    tick(mon, now)
    assert sent.messages[-1] == ("repair", "Reservierung", gh.report)
    assert gh.blob_auth is None  # the GitHub key is not sent on to the download server
    tick(mon, now, 2)
    assert [m[0] for m in sent.messages].count("repair") == 1
    last = c.get("/api/uptime", headers=H).json()["apps"][0]["repair"]
    assert last["state"] == "done" and last["status"] == "fixed" and last["branch"] == "claude/auto-repair-77"

    # Back up, and down again within the hour: no new AI run (cost); after an hour it may run again.
    gh.site = (200, "ok"); tick(mon, now)
    gh.site = (503, "down"); tick(mon, now, 2)
    assert len(gh.dispatched) == 1 and sent.messages[-1] == ("down", "Reservierung", "http_503", False)
    gh.site = (200, "ok"); now[0] += timedelta(hours=1); tick(mon, now)
    gh.site = (503, "down"); tick(mon, now, 2)
    assert len(gh.dispatched) == 2 and sent.messages[-1][3] is True


def test_without_key_the_alarm_still_goes_out_and_nothing_is_started(tmp_path):
    store, c, saved, gh, sent, now, mon = setup(tmp_path, token=False)
    assert c.get("/api/uptime", headers=H).json()["repair_ready"] is False
    tick(mon, now, 2)
    assert sent.messages == [("down", "Reservierung", "http_503", False)] and gh.dispatched == []
    assert c.post(f"/api/uptime/{saved['id']}/repair", headers=H, json={}).status_code == 409


def test_job_that_never_reports_back_is_given_up_with_a_message(tmp_path):
    store, c, saved, gh, sent, now, mon = setup(tmp_path)
    tick(mon, now, 2)
    now[0] += timedelta(minutes=95)
    tick(mon, now)
    assert sent.messages[-1][0] == "repair" and sent.messages[-1][2]["status"] == "timeout"


def test_owner_can_start_it_by_hand_and_bad_settings_are_refused(tmp_path):
    store, c, saved, gh, sent, now, mon = setup(tmp_path)
    r = c.post(f"/api/uptime/{saved['id']}/repair", headers=H, json={})
    assert r.status_code == 200
    assert c.get("/api/uptime", headers=H).json()["apps"][0]["repair"]["state"] == "running"
    assert c.post(f"/api/uptime/{saved['id']}/repair", headers=H, json={}).status_code == 429  # not twice in 10 minutes
    assert c.post("/api/uptime/nope/repair", headers=H, json={}).status_code == 404
    assert c.post(f"/api/uptime/{saved['id']}/repair", json={}).status_code == 403
    for bad in ("o/res/x", "https://github.com/o/res", "o res", "../x"):
        assert c.post("/api/apps", headers=H, json={"name": "x", "url": "https://x.test/", "repair_repo": bad}).status_code == 422
    assert c.post("/api/apps", headers=H, json={"name": "x", "url": "https://x.test/", "repair_token": "kurz"}).status_code == 422
    # Saving the program again without a key keeps the stored key.
    c.post("/api/apps", headers=H, json={"id": saved["id"], "name": "Reservierung", "url": "https://res.test/", "repair_repo": "o/res"})
    assert store.get_setting(TOKEN_KEY) == PAT


def test_github_refusal_is_reported_not_hidden(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    t = httpx.MockTransport(lambda req: httpx.Response(403, json={"message": "Resource not accessible"}))
    assert GitHubRepair(store, transport=t).dispatch("o/res", "abc", "http_503") is False
    store.set_setting(APPS_KEY, [])
