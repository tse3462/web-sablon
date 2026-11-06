"""Uptime monitoring of the owner's own programs ("My apps"), like UptimeRobot (user request 06.11.2026).

Every minute each monitored program is fetched: its address, or a separate check address such as
``https://reservierung.bnl-digital.de/health`` together with an expected text such as
``"database":"ok"`` -- that way the program's database is checked too, without ever storing a
database password here. Two failed checks in a row send one "down" message; the first good check
afterwards sends "back up after N minutes". HTTPS certificates are checked every six hours and
reported once a day when they expire within 14 days. Results are kept for 30 days.
"""

from __future__ import annotations

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

APPS_KEY = "apps"
STATE_KEY = "uptime_state"
FAILURES_BEFORE_ALERT = 2
KEEP = timedelta(days=30)
SSL_EVERY = timedelta(hours=6)
SSL_WARN_DAYS = 14
TIMEOUT_S = 10.0
BARS = 30

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
    def uptime_down(self, app_id: str, name: str, reason: str) -> Any: ...
    def uptime_up(self, app_id: str, name: str, minutes: int) -> Any: ...
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
    def __init__(self, store, notifier: UptimeNotifier | None, transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], datetime] = utcnow, ssl_days: Callable[[str], int | None] = certificate_days_left):
        self.store, self.notifier, self.transport, self.clock, self.ssl_days = store, notifier, transport, clock, ssl_days
        self._lock = threading.Lock()
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
    def run_once(self) -> None:
        with self._lock:  # the server loop and "check now" in the panel never overlap
            now = self.clock()
            state = self._state()
            apps = self.apps()
            for a in apps:
                if a.get("monitor", True) is False:
                    continue
                url = a.get("check_url") or a.get("url")
                if not url:
                    continue
                res = check_target(url, a.get("keyword") or None, transport=self.transport)
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
                    st.setdefault("down_since", None)
                    if not st["down_since"]:
                        st["down_since"] = _iso(now)
                    st["reason"] = res.error
                    if st["fails"] >= FAILURES_BEFORE_ALERT and not st.get("alerted"):
                        self._notify("uptime_down", a["id"], a["name"], res.error or "down")
                        st["alerted"] = True
                self._check_certificate(a, url, st, now)
            known = {a["id"] for a in apps}
            state = {k: v for k, v in state.items() if k in known}
            self.store.set_setting(STATE_KEY, state)
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
            rows = self.store._q("select at, ok, code, ms, error from uptime_checks where app_id=? and at>=? order by at",
                                 (a["id"], _iso(now - KEEP)))
            day = [r for r in rows if _parse(r["at"]) >= now - timedelta(days=1)]
            week = [r for r in rows if _parse(r["at"]) >= now - timedelta(days=7)]

            def pct(xs):
                return round(100.0 * sum(r["ok"] for r in xs) / len(xs), 2) if xs else None

            last = rows[-1] if rows else None
            st = state.get(a["id"], {})
            status = "paused" if not monitored else "unknown" if not last else ("up" if last["ok"] else "down")
            bars = ["up" if r["ok"] else "down" for r in rows[-BARS:]]
            ms = [r["ms"] for r in day if r["ok"] and r["ms"] is not None]
            out.append({
                "id": a["id"], "name": a.get("name", ""), "url": a.get("url", ""), "check_url": a.get("check_url") or a.get("url"),
                "keyword": a.get("keyword") or None, "monitored": monitored, "status": status,
                "down_since": st.get("down_since") if status == "down" else None, "reason": st.get("reason") if status == "down" else None,
                "last_at": last["at"] if last else None, "last_ms": last["ms"] if last else None,
                "avg_ms_24h": round(sum(ms) / len(ms)) if ms else None,
                "uptime_24h": pct(day), "uptime_7d": pct(week), "uptime_30d": pct(rows),
                "checks_24h": len(day), "checks_30d": len(rows), "ssl_days": st.get("ssl_days"),
                "bars": ["none"] * (BARS - len(bars)) + bars, "incidents": self._incidents(rows)[:10],
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
