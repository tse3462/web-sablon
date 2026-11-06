"""Uptime monitoring of the owner's own programs (user request 06.11.2026, "like UptimeRobot")."""

from datetime import timedelta

import httpx
from fastapi.testclient import TestClient

from bonelia.contracts import utcnow
from bonelia.server.dashboard import APPS_KEY, create_dashboard_app
from bonelia.server.store import Store
from bonelia.server.uptime import UptimeMonitor, check_target

TOKEN = "d" * 32
H = {"x-ui-token": TOKEN}


class Sent:
    """Stands in for the notifier: records what would go to Telegram."""

    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def uptime_down(self, app_id, name, reason, links=None):
        self.messages.append(("down", f"{name}: {reason}"))
        self.links = links

    def internet_back(self, minutes):
        self.messages.append(("internet", str(minutes)))

    def uptime_up(self, app_id, name, minutes):
        self.messages.append(("up", f"{name}: {minutes}"))

    def ssl_expiring(self, app_id, name, days):
        self.messages.append(("ssl", f"{name}: {days}"))


def transport(responses: dict[str, object]):
    def handle(request: httpx.Request) -> httpx.Response:
        answer = responses[str(request.url)]
        if isinstance(answer, Exception):
            raise answer
        code, body = answer
        return httpx.Response(code, text=body)
    return httpx.MockTransport(handle)


def test_check_target_reads_status_keyword_and_failures():
    t = transport({"https://ok.test/": (200, "<html>ok</html>"), "https://db.test/health": (200, '{"status":"ok","database":"ok"}'),
                   "https://down.test/health": (503, '{"database":"unavailable"}'), "https://slow.test/": httpx.ConnectTimeout("t")})
    assert check_target("https://ok.test/", None, transport=t).ok
    assert check_target("https://db.test/health", '"database":"ok"', transport=t).ok
    missing = check_target("https://ok.test/", '"database":"ok"', transport=t)
    assert not missing.ok and missing.error == "keyword_missing" and missing.code == 200
    down = check_target("https://down.test/health", '"database":"ok"', transport=t)
    assert not down.ok and down.code == 503 and down.error == "http_503"
    slow = check_target("https://slow.test/", None, transport=t)
    assert not slow.ok and slow.error == "timeout" and slow.code is None


def test_alert_after_two_failures_then_recovery_with_duration(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(APPS_KEY, [{"id": "res", "name": "Reservierung", "url": "https://res.test/admin",
                                  "check_url": "https://res.test/health", "keyword": '"database":"ok"', "monitor": True},
                                 {"id": "off", "name": "Nicht überwacht", "url": "https://off.test/", "monitor": False}])
    answers = {"https://res.test/health": (200, '{"database":"ok"}')}
    sent, now = Sent(), [utcnow()]
    answers["https://probe.test/"] = (204, "")  # the home internet works
    mon = UptimeMonitor(store, sent, transport=transport(answers), clock=lambda: now[0], ssl_days=lambda host: 90,
                        probes=("https://probe.test/",))

    mon.run_once()
    answers["https://res.test/health"] = (503, '{"database":"unavailable"}')
    now[0] += timedelta(minutes=1); mon.run_once()
    assert sent.messages == []  # one failure can be a hiccup
    now[0] += timedelta(minutes=1); mon.run_once()
    assert sent.messages == [("down", "Reservierung: http_503")]
    now[0] += timedelta(minutes=1); mon.run_once()
    assert len(sent.messages) == 1  # no repeat while it stays down
    answers["https://res.test/health"] = (200, '{"database":"ok"}')
    now[0] += timedelta(minutes=1); mon.run_once()
    assert sent.messages[-1] == ("up", "Reservierung: 3")  # down since the first failed check

    s = {x["id"]: x for x in mon.summary()}
    assert s["res"]["status"] == "up" and s["res"]["checks_24h"] == 5
    assert s["res"]["uptime_24h"] == 40.0
    assert s["res"]["incidents"][0]["minutes"] == 3 and s["res"]["incidents"][0]["reason"] == "http_503"
    assert s["off"]["status"] == "paused" and s["off"]["checks_24h"] == 0
    assert len(s["res"]["bars"]) == 30 and s["res"]["bars"][-1] == "up" and s["res"]["bars"][-2] == "down"


def test_ssl_warning_once_a_day_and_old_checks_are_pruned(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(APPS_KEY, [{"id": "a", "name": "Shop", "url": "https://shop.test/", "monitor": True}])
    sent, now = Sent(), [utcnow()]
    mon = UptimeMonitor(store, sent, transport=transport({"https://shop.test/": (200, "ok")}), clock=lambda: now[0],
                        ssl_days=lambda host: 9)
    mon.run_once(); now[0] += timedelta(minutes=1); mon.run_once()
    assert sent.messages == [("ssl", "Shop: 9")]
    assert mon.summary()[0]["ssl_days"] == 9
    now[0] += timedelta(days=31); mon.run_once()
    assert mon.summary()[0]["checks_30d"] == 1  # checks older than 30 days are removed


def test_panel_saves_check_address_and_shows_uptime(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    c = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999")
    saved = c.post("/api/apps", headers=H, json={"name": "Reservierung", "url": "https://res.test/admin",
                                                 "check_url": "https://res.test/health", "keyword": '"database":"ok"'}).json()["apps"][0]
    assert saved["check_url"] == "https://res.test/health" and saved["keyword"] == '"database":"ok"' and saved["monitor"] is True
    assert c.post("/api/apps", headers=H, json={"name": "x", "url": "https://x.test/", "check_url": "ftp://x"}).status_code == 422
    UptimeMonitor(store, Sent(), transport=transport({"https://res.test/health": (200, '{"database":"ok"}')}),
                  ssl_days=lambda host: 60).run_once()
    u = c.get("/api/uptime", headers=H).json()["apps"]
    assert u[0]["name"] == "Reservierung" and u[0]["status"] == "up" and u[0]["uptime_24h"] == 100.0
    assert c.get("/api/uptime").status_code == 403


def test_home_internet_down_is_not_counted_as_program_outage(tmp_path):
    """Everything failing at once is checked against public addresses first (user request 06.11.2026)."""
    store = Store(tmp_path / "db.sqlite")
    store.set_setting(APPS_KEY, [{"id": "a", "name": "Reservierung", "url": "https://a.test/", "monitor": True},
                                 {"id": "b", "name": "Shop", "url": "https://b.test/", "monitor": True}])
    offline = httpx.ConnectError("no route")
    answers = {"https://a.test/": offline, "https://b.test/": offline, "https://probe.test/": offline}
    sent, now = Sent(), [utcnow()]
    mon = UptimeMonitor(store, sent, transport=transport(answers), clock=lambda: now[0], ssl_days=lambda h: 90,
                        probes=("https://probe.test/",))
    for _ in range(3):
        mon.run_once(); now[0] += timedelta(minutes=1)
    assert sent.messages == []  # no false alarms while the home internet is out
    s = {x["id"]: x for x in mon.summary()}
    assert s["a"]["status"] == "local_offline" and s["a"]["bars"][-3:] == ["none", "none", "none"]
    assert s["a"]["uptime_24h"] is None  # those minutes do not count against the program
    answers.update({"https://a.test/": (200, "ok"), "https://b.test/": (200, "ok"), "https://probe.test/": (204, "")})
    mon.run_once()
    assert sent.messages == [("internet", "3")]
    assert {x["id"]: x for x in mon.summary()}["a"]["uptime_24h"] == 100.0

    # Only one program failing while the internet works is a real outage.
    answers["https://b.test/"] = (500, "boom")
    for _ in range(2):
        now[0] += timedelta(minutes=1); mon.run_once()
    assert sent.messages[-1] == ("down", "Shop: http_500")


def test_intervention_links_reach_the_panel_and_the_alarm(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    c = TestClient(create_dashboard_app(store, TOKEN, 9999), base_url="http://127.0.0.1:9999")
    links = "Supabase https://supabase.com/dashboard/project/abc\nGitHub: https://github.com/x/y/actions\nkaputt\nftp://nein"
    saved = c.post("/api/apps", headers=H, json={"name": "Reservierung", "url": "https://res.test/", "links": links}).json()["apps"][0]
    assert saved["links"] == [{"label": "Supabase", "url": "https://supabase.com/dashboard/project/abc"},
                              {"label": "GitHub", "url": "https://github.com/x/y/actions"}]
    sent = Sent()
    mon = UptimeMonitor(store, sent, transport=transport({"https://res.test/": (503, "x"), "https://probe.test/": (204, "")}),
                        ssl_days=lambda h: 90, probes=("https://probe.test/",))
    mon.run_once(); mon.run_once()
    assert sent.messages == [("down", "Reservierung: http_503")] and sent.links == saved["links"]
    assert c.get("/api/uptime", headers=H).json()["apps"][0]["links"] == saved["links"]
