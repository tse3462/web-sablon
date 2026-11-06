"""Uptime monitoring of the owner's own programs ("My apps"), like UptimeRobot (user request 06.11.2026).

Every minute each monitored program is fetched: its address, or a separate check address such as
``https://reservierung.bnl-digital.de/health`` together with an expected text such as
``"database":"ok"`` -- that way the program's database is checked too, without ever storing a
database password here. Two failed checks in a row send one "down" message; the first good check
afterwards sends "back up after N minutes". HTTPS certificates are checked every six hours and
reported once a day when they expire within 14 days. Results are kept for 30 days.

When every program fails at the same moment, public addresses are tried first: if those fail too, the
home internet is out. Those checks are stored as "could not check" (not counted against the programs,
no false alarm), and one "internet back after N minutes" message follows. Each program can carry
intervention links (Supabase, Cloudflare, GitHub …) that appear in the panel and in the down message.
"""

from __future__ import annotations

import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

import httpx

from ..contracts import utcnow
from .repair import GitHubRepair

APPS_KEY = "apps"
STATE_KEY = "uptime_state"
FAILURES_BEFORE_ALERT = 2
KEEP = timedelta(days=30)
SSL_EVERY = timedelta(hours=6)
SSL_WARN_DAYS = 14
TIMEOUT_S = 10.0
BARS = 30
# Public addresses that answer quickly: when every program fails at once, these tell whether the
# home internet is out (then nothing is counted against the programs and no false alarm goes out).
PROBES = ("https://www.google.com/generate_204", "https://1.1.1.1/", "https://www.cloudflare.com/cdn-cgi/trace")
LOCAL_OFFLINE = "local_offline"
REPAIR_EVERY = timedelta(hours=1)        # at most one AI run per program and hour (each run costs money)
REPAIR_BY_HAND_EVERY = timedelta(minutes=10)
REPAIR_GIVE_UP = timedelta(minutes=90)

SCHEMA = """
create table if not exists uptime_checks (
  id integer primary key autoincrement, app_id text not null, at text not null,
  ok integer not null, code integer, ms integer, error text);
create index if not exists uptime_checks_app_at on uptime_checks(app_id, at);
"""


@dataclass
class CheckResult:
    ok: bool
    code: int | None
    ms: int
    error: str | None


class UptimeNotifier(Protocol):
    def uptime_down(self, app_id: str, name: str, reason: str, links: list[dict] | None = None, repair: bool = False) -> Any: ...
    def repair_result(self, app_id: str, name: str, request_id: str, report: dict) -> Any: ...
    def uptime_up(self, app_id: str, name: str, minutes: int) -> Any: ...
    def internet_back(self, minutes: int) -> Any: ...
    def ssl_expiring(self, app_id: str, name: str, days: int) -> Any: ...


def check_target(url: str, keyword: str | None, transport: httpx.BaseTransport | None = None,
                 timeout: float = TIMEOUT_S) -> CheckResult:
    """One request: up when the answer is 2xx/3xx and, if given, contains the expected text."""
    start = time.monotonic()
    try:
        with httpx.Client(transport=transport, timeout=timeout, follow_redirects=True,
                          headers={"user-agent": "BONELIA-AI-Uptime/1.0"}) as client:
            r = client.get(url)
        ms = int((time.monotonic() - start) * 1000)
        if not 200 <= r.status_code < 400:
            return CheckResult(False, r.status_code, ms, f"http_{r.status_code}")
        if keyword and keyword not in r.text:
            return CheckResult(False, r.status_code, ms, "keyword_missing")
        return CheckResult(True, r.status_code, ms, None)
    except httpx.TimeoutException:
        return CheckResult(False, None, int((time.monotonic() - start) * 1000), "timeout")
    except httpx.ConnectError as exc:
        reason = "ssl" if "certificate" in str(exc).lower() or "ssl" in str(exc).lower() else "connection"
        return CheckResult(False, None, int((time.monotonic() - start) * 1000), reason)
    except httpx.HTTPError:
        return CheckResult(False, None, int((time.monotonic() - start) * 1000), "connection")


_SMART = str.maketrans({"“": '"', "”": '"', "„": '"', "‟": '"', "″": '"', "«": '"', "»": '"',
                        "‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'"})


def normalize_keyword(keyword: str | None) -> str | None:
    """Phones turn typed quotes into curly ones; the program answers with straight ones."""
    k = (keyword or "").translate(_SMART).strip()
    return k or None


def check_settings(a: dict[str, Any]) -> tuple[str | None, str | None]:
    """What is actually measured for a program: the address and the expected text."""
    return (a.get("check_url") or a.get("url") or None, normalize_keyword(a.get("keyword")))


def certificate_days_left(host: str, port: int = 443, timeout: float = TIMEOUT_S) -> int | None:
    """Days until the HTTPS certificate of `host` expires; None when it cannot be read."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return None


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat()


def _parse(s: str) -> datetime:
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class UptimeMonitor:
    # One lock for every monitor in the process: the server loop and the panel's "check now" share the stored state.
    _RUN_LOCK = threading.Lock()

    def __init__(self, store, notifier: UptimeNotifier | None, transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], datetime] = utcnow, ssl_days: Callable[[str], int | None] = certificate_days_left,
                 probes: tuple[str, ...] = PROBES, repair: GitHubRepair | None = None):
        self.store, self.notifier, self.transport, self.clock, self.ssl_days = store, notifier, transport, clock, ssl_days
        self.probes = probes
        self.repair = repair or GitHubRepair(store, transport=transport)
        self._lock = UptimeMonitor._RUN_LOCK
        with store._lock:
            store._db.executescript(SCHEMA)

    # ------------------------------------------------------------------ data
    def apps(self) -> list[dict[str, Any]]:
        apps = self.store.get_setting(APPS_KEY)
        return apps if isinstance(apps, list) else []

    def _state(self) -> dict[str, Any]:
        s = self.store.get_setting(STATE_KEY)
        return s if isinstance(s, dict) else {}

    def _notify(self, method: str, *args: Any) -> None:
        if self.notifier is None:
            return
        try:
            getattr(self.notifier, method)(*args)
        except Exception:  # a broken channel must never stop the monitoring
            pass

    # ------------------------------------------------------------------ checking
    def _internet_ok(self) -> bool:
        for url in self.probes:
            try:
                if check_target(url, None, transport=self.transport, timeout=5.0).ok:
                    return True
            except Exception:
                continue
        return False

    def run_once(self) -> None:
        with self._lock:  # the server loop and "check now" in the panel never overlap
            now = self.clock()
            state = self._state()
            apps = self.apps()
            results = []
            for a in apps:
                if a.get("monitor", True) is False:
                    continue
                url = a.get("check_url") or a.get("url")
                if url:
                    results.append((a, url, check_target(url, normalize_keyword(a.get("keyword")), transport=self.transport)))
            net = state.setdefault("_net", {})
            if results and not any(r.ok for _, _, r in results) and not self._internet_ok():
                # The home internet is out: record "could not check", count nothing against the programs.
                for a, _, _ in results:
                    self.store._x("insert into uptime_checks (app_id, at, ok, code, ms, error) values (?,?,?,?,?,?)",
                                  (a["id"], _iso(now), 0, None, None, LOCAL_OFFLINE))
                net.setdefault("down_since", None)
                if not net["down_since"]:
                    net["down_since"] = _iso(now)
                self._save(state, apps, now)
                return
            if net.get("down_since"):
                minutes = max(1, round((now - _parse(net["down_since"])).total_seconds() / 60))
                self._notify("internet_back", minutes)
                net["down_since"] = None
            for a, url, res in results:
                self.store._x("insert into uptime_checks (app_id, at, ok, code, ms, error) values (?,?,?,?,?,?)",
                              (a["id"], _iso(now), int(res.ok), res.code, res.ms, res.error))
                st = state.setdefault(a["id"], {"fails": 0, "alerted": False})
                if res.ok:
                    if st.get("alerted") and st.get("down_since"):
                        minutes = max(1, round((now - _parse(st["down_since"])).total_seconds() / 60))
                        self._notify("uptime_up", a["id"], a["name"], minutes)
                    st.update(fails=0, alerted=False, down_since=None)
                else:
                    st["fails"] = int(st.get("fails", 0)) + 1
                    if not st.get("down_since"):
                        st["down_since"] = _iso(now)
                    st["reason"] = res.error
                    if st["fails"] >= FAILURES_BEFORE_ALERT and not st.get("alerted"):
                        started = self._start_repair(a, st, now, res.error or "down", REPAIR_EVERY)
                        self._notify("uptime_down", a["id"], a["name"], res.error or "down", a.get("links") or [], started)
                        st["alerted"] = True
                self._check_certificate(a, url, st, now)
            self._poll_repairs(apps, state, now)
            self._save(state, apps, now)

    # ------------------------------------------------------------------ AI repair (GitHub job)
    def _start_repair(self, a: dict[str, Any], st: dict[str, Any], now: datetime, reason: str, every: timedelta) -> bool:
        repo = a.get("repair_repo")
        if not repo or not self.repair.ready():
            return False
        if st.get("repair_at") and now - _parse(st["repair_at"]) < every:
            return False
        rid = secrets.token_hex(8)
        try:
            ok = self.repair.dispatch(repo, rid, reason)
        except Exception:
            ok = False
        if ok:
            st.update(repair_at=_iso(now), repair_rid=rid, repair_repo=repo)
        return ok

    def _poll_repairs(self, apps: list[dict[str, Any]], state: dict[str, Any], now: datetime) -> None:
        for a in apps:
            st = state.get(a["id"]) or {}
            rid = st.get("repair_rid")
            if not rid:
                continue
            try:
                report = self.repair.result(st.get("repair_repo") or a.get("repair_repo"), rid)
            except Exception:
                report = None  # GitHub not reachable: try again next minute
            if report is None and now - _parse(st["repair_at"]) > REPAIR_GIVE_UP:
                report = {"status": "timeout", "cause": None, "summary": "", "branch": None, "run_url": None}
            if report is None:
                continue
            self._notify("repair_result", a["id"], a.get("name", ""), rid, report)
            st["repair_last"] = {"at": _iso(now), **{k: report.get(k) for k in ("status", "cause", "summary", "branch", "run_url")}}
            st.pop("repair_rid", None)

    def start_repair_by_hand(self, app_id: str) -> str:
        """The panel's "let the AI look" button: "started", "unknown_app", "no_repo", "no_token", "too_soon" or "refused"."""
        with self._lock:
            app = next((a for a in self.apps() if a.get("id") == app_id), None)
            if app is None:
                return "unknown_app"
            if not app.get("repair_repo"):
                return "no_repo"
            if not self.repair.ready():
                return "no_token"
            state, now = self._state(), self.clock()
            st = state.setdefault(app_id, {"fails": 0, "alerted": False})
            if st.get("repair_rid") or (st.get("repair_at") and now - _parse(st["repair_at"]) < REPAIR_BY_HAND_EVERY):
                return "too_soon"
            if not self._start_repair(app, st, now, "manual", REPAIR_BY_HAND_EVERY):
                return "refused"
            self.store.set_setting(STATE_KEY, state)
            return "started"

    def reset(self, app_id: str) -> None:
        """Forget a program's history, e.g. after its check address was corrected (old results measured something else)."""
        with self._lock:
            self.store._x("delete from uptime_checks where app_id=?", (app_id,))
            state = self._state()
            if state.pop(app_id, None) is not None:
                self.store.set_setting(STATE_KEY, state)

    def _save(self, state: dict[str, Any], apps: list[dict[str, Any]], now: datetime) -> None:
        known = {a["id"] for a in apps}
        self.store.set_setting(STATE_KEY, {k: v for k, v in state.items() if k in known or k.startswith("_")})
        self.store._x("delete from uptime_checks where at < ?", (_iso(now - KEEP),))

    def _check_certificate(self, a: dict[str, Any], url: str, st: dict[str, Any], now: datetime) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            st["ssl_days"] = None
            return
        if st.get("ssl_at") and now - _parse(st["ssl_at"]) < SSL_EVERY:
            return
        days = self.ssl_days(parts.hostname)
        st.update(ssl_days=days, ssl_at=_iso(now))
        if days is not None and days < SSL_WARN_DAYS:
            day = now.date().isoformat()
            if st.get("ssl_warned") != day:
                self._notify("ssl_expiring", a["id"], a["name"], days)
                st["ssl_warned"] = day

    # ------------------------------------------------------------------ panel view
    def summary(self) -> list[dict[str, Any]]:
        now = self.clock()
        state = self._state()
        out = []
        for a in self.apps():
            monitored = a.get("monitor", True) is not False and bool(a.get("check_url") or a.get("url"))
            all_rows = self.store._q("select at, ok, code, ms, error from uptime_checks where app_id=? and at>=? order by at",
                                     (a["id"], _iso(now - KEEP)))
            rows = [r for r in all_rows if r["error"] != LOCAL_OFFLINE]  # home internet out: not the program's fault
            day = [r for r in rows if _parse(r["at"]) >= now - timedelta(days=1)]
            week = [r for r in rows if _parse(r["at"]) >= now - timedelta(days=7)]

            def pct(xs):
                return round(100.0 * sum(r["ok"] for r in xs) / len(xs), 2) if xs else None

            last = rows[-1] if rows else None
            st = state.get(a["id"], {})
            status = ("paused" if not monitored else "local_offline" if all_rows and all_rows[-1]["error"] == LOCAL_OFFLINE
                      else "unknown" if not last else ("up" if last["ok"] else "down"))
            bars = ["none" if r["error"] == LOCAL_OFFLINE else "up" if r["ok"] else "down" for r in all_rows[-BARS:]]
            ms = [r["ms"] for r in day if r["ok"] and r["ms"] is not None]
            out.append({
                "id": a["id"], "name": a.get("name", ""), "url": a.get("url", ""), "check_url": a.get("check_url") or a.get("url"),
                "keyword": a.get("keyword") or None, "monitored": monitored, "status": status, "links": a.get("links") or [],
                "down_since": st.get("down_since") if status == "down" else None, "reason": st.get("reason") if status == "down" else None,
                "last_at": all_rows[-1]["at"] if all_rows else None, "last_ms": last["ms"] if last else None,
                "avg_ms_24h": round(sum(ms) / len(ms)) if ms else None,
                "uptime_24h": pct(day), "uptime_7d": pct(week), "uptime_30d": pct(rows),
                "checks_24h": len(day), "checks_30d": len(rows), "ssl_days": st.get("ssl_days"),
                "bars": ["none"] * (BARS - len(bars)) + bars, "incidents": self._incidents(rows)[:10],
                "repair_repo": a.get("repair_repo") or None,
                "repair": ({"state": "running", "at": st.get("repair_at")} if st.get("repair_rid")
                           else {"state": "done", **st["repair_last"]} if st.get("repair_last") else None),
            })
        return out

    @staticmethod
    def _incidents(rows: list[Any]) -> list[dict[str, Any]]:
        """Runs of failed checks, newest first: start, end (None while still down), minutes, reason."""
        out, start, reason = [], None, None
        for r in rows:
            if not r["ok"] and start is None:
                start, reason = r["at"], r["error"]
            elif r["ok"] and start is not None:
                out.append({"start": start, "end": r["at"], "reason": reason,
                            "minutes": max(1, round((_parse(r["at"]) - _parse(start)).total_seconds() / 60))})
                start = None
        if start is not None:
            out.append({"start": start, "end": None, "reason": reason, "minutes": None})
        return list(reversed(out))
