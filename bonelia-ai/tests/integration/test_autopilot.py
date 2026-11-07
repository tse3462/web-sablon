"""Autopilot of the own programs (owner decision 07.11.2026): known problems are fixed without asking, a fix goes
live by itself only inside narrow limits, and the owner hears at once only what the autopilot could not solve."""

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient

from bonelia.server.autopilot import DIGEST_KEY, Autopilot, guardrails, read_db_stats
from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.repair import TOKEN_KEY, GitHubRepair
from bonelia.server.store import Store
from bonelia.server.uptime import STATE_KEY, UptimeMonitor

PAT = "github_pat_" + "A1b2" * 10
API = "https://api.github.com/repos/o/res"
TOKEN = "d" * 32
TITLES = {"geri-al.yml": "Geri al", "db-bakim.yml": "DB bakim", "auto-repair.yml": "Auto repair"}
ARTS = {"geri-al.yml": "geri-al-report", "db-bakim.yml": "db-bakim-report", "auto-repair.yml": "auto-repair-report"}
SMALL = [{"filename": "src/api/server.ts", "additions": 3, "deletions": 1}]


def zipped(rep):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("report.json", json.dumps(rep))
    return buf.getvalue()


class GH:
    """The program's site and its GitHub repository."""

    def __init__(self):
        self.site = (500, "Worker threw exception")
        self.jobs: list[dict] = []          # every dispatched job: workflow, inputs, done, report
        self.reports = {"geri-al.yml": {"status": "rolled_back", "healthy": True},
                        "db-bakim.yml": {"status": "done", "terminated": 3, "cancelled": 0},
                        "auto-repair.yml": {"status": "fixed", "cause": "code", "summary": "Bir değişken yanlış yazılmıştı.",
                                            "branch": "claude/auto-repair-90", "run_url": "https://github.com/o/res/actions/runs/90"}}
        self.files = SMALL
        self.merged: list[dict] = []
        self.deploy = None                  # conclusion of the Deploy run of the merged commit
        self.transport = httpx.MockTransport(self.handle)

    def finish(self, workflow):
        for j in self.jobs:
            if j["workflow"] == workflow:
                j["done"] = True

    def handle(self, req):
        url = str(req.url)
        if url.startswith("https://res.test/"):
            return httpx.Response(self.site[0], text=self.site[1])
        if url == "https://probe.test/":
            return httpx.Response(204)
        assert req.headers["authorization"] == f"Bearer {PAT}"
        for wf in TITLES:
            if req.method == "POST" and url == f"{API}/actions/workflows/{wf}/dispatches":
                self.jobs.append({"workflow": wf, "inputs": json.loads(req.content)["inputs"], "done": False})
                return httpx.Response(204)
            if url.startswith(f"{API}/actions/workflows/{wf}/runs"):
                runs = [{"id": 100 + i, "display_title": f"{TITLES[wf]} {j['inputs']['request_id']}",
                         "status": "completed" if j["done"] else "in_progress", "html_url": f"https://github.com/o/res/actions/runs/{100 + i}"}
                        for i, j in enumerate(self.jobs) if j["workflow"] == wf]
                return httpx.Response(200, json={"workflow_runs": runs})
        if "/artifacts" in url and "/runs/" in url:
            i = int(url.split("/runs/")[1].split("/")[0]) - 100
            return httpx.Response(200, json={"artifacts": [{"name": ARTS[self.jobs[i]["workflow"]], "expired": False,
                                                            "archive_download_url": f"https://blob.test/{i}"}]})
        if url.startswith("https://blob.test/"):
            return httpx.Response(200, content=zipped(self.reports[self.jobs[int(url.rsplit('/', 1)[1])]["workflow"]]))
        if url == f"{API}/compare/main...claude/auto-repair-90":
            return httpx.Response(200, json={"files": self.files, "behind_by": 0})
        if req.method == "POST" and url == f"{API}/merges":
            self.merged.append(json.loads(req.content))
            return httpx.Response(201, json={"sha": "f" * 40})
        if url.startswith(f"{API}/actions/workflows/deploy.yml/runs"):
            runs = [{"head_sha": "f" * 40, "status": "completed", "conclusion": self.deploy}] if self.deploy else []
            return httpx.Response(200, json={"workflow_runs": runs})
        return httpx.Response(404)


class Sent:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *a: self.calls.append((name, a))

    def names(self):
        return [c[0] for c in self.calls]


def setup(tmp_path, start=datetime(2026, 11, 7, 1, 0, tzinfo=timezone.utc)):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(TOKEN_KEY, PAT)
    store.set_setting(APPS_KEY, [{"id": "r1", "name": "Rezervasyon", "url": "https://res.test/", "check_url": "https://res.test/health",
                                  "repair_repo": "o/res"}])
    gh, sent, now = GH(), Sent(), [start]
    mon = UptimeMonitor(store, sent, transport=gh.transport, clock=lambda: now[0], ssl_days=lambda h: 90, probes=("https://probe.test/",))
    return store, gh, sent, now, mon


def tick(mon, now, n=1):
    for _ in range(n):
        mon.run_once()
        now[0] += timedelta(minutes=1)


def state(store):
    return store.get_setting(STATE_KEY)["r1"]


def test_a_bad_deployment_is_rolled_back_fixed_and_shipped_while_the_owner_sleeps(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    tick(mon, now, 2)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml"] and sent.calls == []  # at night: no message yet
    gh.finish("geri-al.yml")
    gh.site = (200, '{"status":"ok","database":"ok"}')
    tick(mon, now)
    repair = gh.jobs[1]
    assert repair["workflow"] == "auto-repair.yml" and repair["inputs"]["reason"].startswith("rolled_back:")
    assert "uptime_up" not in sent.names()  # back up quietly: it goes into the morning summary
    gh.finish("auto-repair.yml")
    tick(mon, now)
    assert gh.merged == [{"base": "main", "head": "claude/auto-repair-90", "commit_message": gh.merged[0]["commit_message"]}]
    assert state(store)["pilot"]["phase"] == "deploying"
    tick(mon, now, 3)
    gh.deploy = "success"
    tick(mon, now)
    st = state(store)
    assert "pilot" not in st and st["pilot_last"]["minutes"] >= 5 and sent.calls == []
    digest = store.get_setting(DIGEST_KEY)
    assert len(digest) == 1 and "kendiliğinden çözüldü" in digest[0]["text"] and "canlıda" in digest[0]["text"]
    pilot = Autopilot(store, GitHubRepair(store, gh.transport), sent)
    assert pilot.send_digest(datetime(2026, 11, 7, 6, 30, tzinfo=timezone.utc)) is False  # 07:30 in Berlin
    assert pilot.send_digest(datetime(2026, 11, 7, 7, 5, tzinfo=timezone.utc)) is True   # 08:05
    assert sent.names() == ["pilot_digest"] and store.get_setting(DIGEST_KEY) == []
    assert pilot.send_digest(datetime(2026, 11, 7, 9, 0, tzinfo=timezone.utc)) is False  # once a day
    assert pilot.ai_runs(now[0]) == 1


def test_a_fix_outside_the_limits_waits_for_the_owner(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    gh.files = [{"filename": "db/migrations/080_fix.sql", "additions": 5, "deletions": 0}]
    tick(mon, now, 2)
    gh.finish("geri-al.yml")
    gh.site = (200, '{"database":"ok"}')
    tick(mon, now)
    gh.finish("auto-repair.yml")
    tick(mon, now, 2)
    assert gh.merged == [] and sent.names() == ["pilot_waiting"]
    st = state(store)
    assert "pilot" not in st and st["pilot_wait"]["branch"] == "claude/auto-repair-90" and st["pilot_wait"]["why"].startswith("protected:")
    import bonelia.server.autopilot  # noqa: F401
    c = TestClient(create_dashboard_app(store, TOKEN, 9999, http_transport=gh.transport), base_url="http://127.0.0.1:9999",
                   headers={"x-ui-token": TOKEN})
    view = c.get("/api/pilot").json()
    assert view["apps"][0]["waiting"]["branch"] == "claude/auto-repair-90" and view["ai_cap"] == 30
    assert c.post("/api/pilot/r1/approve", json={}).json()["result"] == "merged" and len(gh.merged) == 1
    assert c.post("/api/pilot/r1/approve", json={}).status_code == 409
    assert c.post("/api/pilot/settings", json={"app_id": "r1", "on": False}).json()["apps"][0]["on"] is False
    assert c.post("/api/pilot/settings", json={"ai_cap": 10}).json()["ai_cap"] == 10
    html = c.get("/").text
    assert 'id="pilotBox"' in html and "function pilotLoad(" in html
    for key in ("ap_title", "ap_help", "ap_on", "ap_cap", "ap_wait", "ap_approve", "ap_digest", "ap_db_off"):
        assert html.count(key + ":") == 2


def test_database_down_gets_first_aid_when_nothing_was_deployed(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    gh.site = (503, '{"status":"degraded","database":"unavailable"}')
    gh.reports["geri-al.yml"] = {"status": "refused", "reason": "no_recent_deploy", "healthy": False}
    tick(mon, now, 2)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml"]  # a fresh deployment is checked first, always
    gh.finish("geri-al.yml")
    tick(mon, now)
    assert [(j["workflow"], j["inputs"].get("action")) for j in gh.jobs][1] == ("db-bakim.yml", "stuck")
    gh.finish("db-bakim.yml")
    gh.site = (200, '{"database":"ok"}')
    tick(mon, now, 2)
    assert "pilot" not in state(store) and sent.calls == [] and len(gh.jobs) == 2  # solved: no AI run, no money spent
    assert "3 takılmış bağlantı" in store.get_setting(DIGEST_KEY)[0]["text"]


def test_a_503_right_after_a_deployment_is_rolled_back(tmp_path):
    """07.11.2026, seen live: a release made the Worker refuse its configuration and /health answered 503. That is not
    the database: going back to the version before the deployment healed it within a minute."""
    store, gh, sent, now, mon = setup(tmp_path)
    gh.site = (503, '{"error":{"code":"SERVICE_UNAVAILABLE"}}')
    tick(mon, now, 2)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml"]
    gh.finish("geri-al.yml")
    gh.site = (200, '{"database":"ok"}')
    tick(mon, now)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml", "auto-repair.yml"]  # then Claude fixes main


def test_what_it_cannot_solve_reaches_the_owner_at_once(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    gh.reports["geri-al.yml"] = {"status": "refused", "reason": "no_recent_deploy", "healthy": False}
    gh.reports["auto-repair.yml"] = {"status": "no_fix", "cause": "external", "summary": "Cloudflare'de kesinti var.", "branch": None}
    tick(mon, now, 2)
    gh.finish("geri-al.yml")
    tick(mon, now)
    gh.finish("auto-repair.yml")
    tick(mon, now)
    assert sent.names() == ["pilot_alert"]
    lines = sent.calls[0][1][1]
    assert any("son 6 saatte yükleme yok" in x for x in lines) and any("Cloudflare" in x for x in lines)
    tick(mon, now, 20)
    assert sent.names() == ["pilot_alert"]  # once
    gh.site = (200, '{"database":"ok"}')
    tick(mon, now)
    assert sent.names() == ["pilot_alert", "uptime_up", "pilot_resolved"]


def test_a_shipped_fix_that_does_not_help_is_taken_back(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    gh.reports["geri-al.yml"] = {"status": "refused", "reason": "no_recent_deploy"}
    tick(mon, now, 2)
    gh.finish("geri-al.yml")
    tick(mon, now)
    gh.finish("auto-repair.yml")
    tick(mon, now)
    gh.deploy = "failure"
    tick(mon, now)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml", "auto-repair.yml", "geri-al.yml"]
    tick(mon, now)
    assert "pilot_alert" in sent.names()


def test_limits_money_and_switch(tmp_path):
    ok, why = guardrails(SMALL)
    assert ok and why == "ok"
    for files, reason in (([{"filename": f"src/a{i}.ts", "additions": 1, "deletions": 0} for i in range(6)], "too_many_files"),
                          ([{"filename": "src/a.ts", "additions": 150, "deletions": 60}], "too_large"),
                          ([{"filename": "package.json", "additions": 1, "deletions": 1}], "protected:package.json"),
                          ([{"filename": "src/billing/stripe-checkout.ts", "additions": 1, "deletions": 1}], "protected:src/billing/stripe-checkout.ts"),
                          ([{"filename": "src/x.ts", "previous_filename": ".github/workflows/deploy.yml", "additions": 0, "deletions": 0}],
                           "protected:.github/workflows/deploy.yml"),
                          ([], "empty")):
        assert guardrails(files) == (False, reason)
    store, gh, sent, now, mon = setup(tmp_path)
    store.set_setting("autopilot", {"ai_cap": 0})
    gh.reports["geri-al.yml"] = {"status": "refused", "reason": "no_recent_deploy"}
    tick(mon, now, 2)
    gh.finish("geri-al.yml")
    tick(mon, now)
    assert [j["workflow"] for j in gh.jobs] == ["geri-al.yml"] and sent.names() == ["pilot_alert"]  # no AI over the cap
    store.set_setting("autopilot", {"off": ["r1"]})
    assert mon.pilot.enabled(store.get_setting(APPS_KEY)[0]) is False


def test_database_figures_every_five_minutes(tmp_path):
    store, gh, sent, now, mon = setup(tmp_path)
    pilot, app = mon.pilot, store.get_setting(APPS_KEY)[0]
    calm = {"connections": 10, "max_connections": 60, "stuck": 0, "long_running": 0}
    stuck = {**calm, "stuck": 2}
    assert pilot.db_check(app, calm, now[0]) is None
    assert pilot.db_check(app, stuck, now[0]) is None                      # once can be a moment
    assert pilot.db_check(app, stuck, now[0] + timedelta(minutes=5)) == "stuck"
    assert pilot.db_check(app, stuck, now[0] + timedelta(minutes=10)) is None  # at most every 30 minutes
    assert [j["inputs"]["action"] for j in gh.jobs] == ["stuck"] and sent.calls == []
    full = {**calm, "connections": 57}
    for m in range(3):
        pilot.db_check(app, full, now[0] + timedelta(minutes=40 + 5 * m))
    assert sent.names() == ["pilot_alert"]

    class Con:
        def cursor(self):
            return self

        def execute(self, sql):
            self.sql = sql

        def fetchone(self):
            return (12, 60, 1, 0)

        def close(self):
            pass
    seen = {}

    def connect(**kw):
        seen.update(kw)
        return Con()
    url = "postgresql://bonelia_health_monitor.abc:p%40ss@aws-1-eu-central-1.pooler.supabase.com:5432/postgres?sslmode=no-verify"
    assert read_db_stats(url, connect) == {"connections": 12, "max_connections": 60, "stuck": 1, "long_running": 0}
    assert seen["user"] == "bonelia_health_monitor.abc" and seen["password"] == "p@ss" and seen["database"] == "postgres"
    assert read_db_stats("https://x", connect) is None

    def broken(**kw):
        raise OSError("refused")
    assert read_db_stats(url, broken) is None
