"""Autopilot of the own programs (owner decision 07.11.2026).

"Known problems are fixed without asking me; Claude may report, but in an emergency it acts." Checks are free
(BONELIA's minute check, the database every 5 minutes); money is spent only when something is wrong.

When a program with a GitHub repository goes down:

1. first aid, at once and without asking:
   - the database answers "unavailable" (HTTP 503)  -> ``db-bakim.yml``: the app's stuck sessions are ended;
   - anything else (the code broke)                  -> ``geri-al.yml``: back to the version live before the
     newest deployment (the job refuses when nothing was deployed lately or it already went back);
2. Claude looks for the cause (``auto-repair.yml``). After a rollback it fixes the faulty code on main, so the
   next deployment does not bring the error back;
3. Claude's fix goes live without asking only inside narrow limits: all CI checks passed, at most 5 files and
   200 lines, nothing in database migrations, workflows, dependencies, payments, sign-in or legal texts, at most
   2 per program and day. Then the normal CI -> Deploy runs; if the site is not healthy after it, back again.
   Outside the limits the fix waits for the owner ("Onayla" in the panel);
4. the owner hears at once only what the autopilot could not solve (still down after 15 minutes, a fix waiting,
   a failed deployment). Everything else goes into one morning summary at 08:00.
"""

from __future__ import annotations

import io
import json
import re
import secrets
import ssl
import zipfile
from datetime import datetime, timedelta
from typing import Any, Callable
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo

import httpx

from ..contracts import utcnow
from .repair import API, GitHubRepair, valid_repo

SETTINGS_KEY = "autopilot"          # {"off": [app ids], "ai_cap": 30}
DIGEST_KEY = "autopilot_digest"     # [{"at", "app", "text"}] until the morning summary
RUNS_KEY = "autopilot_ai_runs"      # {"2026-11": n}
DB_URLS_KEY = "db_monitor_urls"     # {app id: monitor role URL}, set by the setup guide
DB_STATE_KEY = "db_monitor_state"
ROLLBACK, FIRST_AID, REPAIR = "geri-al.yml", "db-bakim.yml", "auto-repair.yml"
TITLES = {ROLLBACK: "Geri al", FIRST_AID: "DB bakim", REPAIR: "Auto repair"}
ARTIFACTS = {ROLLBACK: "geri-al-report", FIRST_AID: "db-bakim-report", REPAIR: "auto-repair-report"}
MAX_FILES, MAX_LINES, MAX_MERGES_PER_DAY, AI_CAP = 5, 200, 2, 30
ALERT_AFTER = timedelta(minutes=15)
JOB_TIMEOUT = {ROLLBACK: timedelta(minutes=20), FIRST_AID: timedelta(minutes=20), REPAIR: timedelta(minutes=90)}
DEPLOY_TIMEOUT = timedelta(minutes=40)
UNHEALTHY_AFTER_DEPLOY = timedelta(minutes=10)
DIGEST_HOUR, TZ = 8, ZoneInfo("Europe/Berlin")
# Files a fix must not touch to go live without the owner: schema, pipelines, dependencies, money, sign-in, law.
PROTECTED = re.compile(r"(^|/)(db|migrations?|\.github)/|(^|/)(package(-lock)?\.json|wrangler\.jsonc?|pyproject\.toml)$"
                       r"|(^|/)src/billing/|stripe|(^|/)(auth|login|session|mfa|password|permission|legal|impressum|datenschutz|agb|avv)",
                       re.I)


def _iso(d: datetime) -> str:
    return d.isoformat()


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


def guardrails(files: list[dict[str, Any]]) -> tuple[bool, str]:
    """May this change go live without the owner? (files as GitHub's compare API lists them)"""
    if not files:
        return False, "empty"
    if len(files) > MAX_FILES:
        return False, "too_many_files"
    if sum(int(f.get("additions", 0)) + int(f.get("deletions", 0)) for f in files) > MAX_LINES:
        return False, "too_large"
    for f in files:
        for name in (str(f.get("filename") or ""), str(f.get("previous_filename") or "")):
            if name and PROTECTED.search(name):
                return False, "protected:" + name[:80]
    return True, "ok"


class PilotGitHub:
    """The GitHub calls of the autopilot, with the owner's key that BONELIA keeps."""

    def __init__(self, gh: GitHubRepair):
        self.gh = gh

    def dispatch(self, repo: str, workflow: str, rid: str, inputs: dict[str, str] | None = None) -> bool:
        if not self.gh.ready() or not valid_repo(repo):
            return False
        try:
            with self.gh._client() as c:
                r = c.post(f"{API}/repos/{repo}/actions/workflows/{workflow}/dispatches",
                           json={"ref": "main", "inputs": {"request_id": rid, **(inputs or {})}})
            return r.status_code == 204
        except httpx.HTTPError:
            return False

    def report(self, repo: str, workflow: str, rid: str) -> dict[str, Any] | None:
        """The finished job's report.json; None while it runs. A job without a report counts as failed."""
        if workflow == REPAIR:
            return self.gh.result(repo, rid)
        with self.gh._client() as c:
            r = c.get(f"{API}/repos/{repo}/actions/workflows/{workflow}/runs", params={"event": "workflow_dispatch", "per_page": 30})
            r.raise_for_status()
            run = next((x for x in r.json().get("workflow_runs", []) if x.get("display_title") == f"{TITLES[workflow]} {rid}"), None)
            if run is None or run.get("status") != "completed":
                return None
            a = c.get(f"{API}/repos/{repo}/actions/runs/{int(run['id'])}/artifacts")
            a.raise_for_status()
            art = next((x for x in a.json().get("artifacts", []) if x.get("name") == ARTIFACTS[workflow] and not x.get("expired")), None)
            if art is None:
                return {"status": "failed", "run_url": run.get("html_url")}
            z = c.get(art["archive_download_url"])
            z.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            rep = json.loads(zf.read("report.json").decode("utf-8"))
        return rep if isinstance(rep, dict) else {"status": "failed"}

    def compare(self, repo: str, branch: str) -> list[dict[str, Any]] | None:
        with self.gh._client() as c:
            r = c.get(f"{API}/repos/{repo}/compare/main...{branch}")
        if r.status_code != 200:
            return None
        return list(r.json().get("files") or [])

    def merge(self, repo: str, branch: str, message: str) -> str | None:
        """Merge with the owner's key (so CI and Deploy start as for any push); the new main commit or None."""
        try:
            with self.gh._client() as c:
                r = c.post(f"{API}/repos/{repo}/merges", json={"base": "main", "head": branch, "commit_message": message})
            return str(r.json().get("sha")) if r.status_code == 201 else None
        except (httpx.HTTPError, ValueError):
            return None

    def deploy_state(self, repo: str, sha: str) -> str | None:
        """'success' / 'failure' once the Deploy of that commit finished; None while CI or Deploy still run."""
        with self.gh._client() as c:
            r = c.get(f"{API}/repos/{repo}/actions/workflows/deploy.yml/runs", params={"head_sha": sha, "per_page": 5})
        if r.status_code != 200:
            return None
        runs = [x for x in r.json().get("workflow_runs") or [] if x.get("head_sha") == sha and x.get("status") == "completed"]
        if any(x.get("conclusion") == "success" for x in runs):
            return "success"
        return "failure" if any(x.get("conclusion") in ("failure", "timed_out", "cancelled") for x in runs) else None


class Autopilot:
    def __init__(self, store, github: GitHubRepair, notifier: Any = None, clock: Callable[[], datetime] = utcnow):
        self.store, self.gh, self.notifier, self.clock = store, PilotGitHub(github), notifier, clock

    # ------------------------------------------------------------------ settings
    def settings(self) -> dict[str, Any]:
        s = self.store.get_setting(SETTINGS_KEY)
        s = s if isinstance(s, dict) else {}
        off = [x for x in s.get("off") or [] if isinstance(x, str)]
        cap = s.get("ai_cap")
        return {"off": off, "ai_cap": int(cap) if isinstance(cap, int) and 0 <= cap <= 500 else AI_CAP}

    def enabled(self, app: dict[str, Any]) -> bool:
        repo = app.get("repair_repo")
        return bool(repo and valid_repo(str(repo)) and self.gh.gh.ready() and app.get("id") not in self.settings()["off"])

    def ai_runs(self, now: datetime | None = None) -> int:
        runs = self.store.get_setting(RUNS_KEY)
        return int((runs or {}).get((now or self.clock()).strftime("%Y-%m"), 0)) if isinstance(runs, dict) else 0

    def _count_ai(self, now: datetime) -> None:
        runs = self.store.get_setting(RUNS_KEY)
        runs = runs if isinstance(runs, dict) else {}
        month = now.strftime("%Y-%m")
        self.store.set_setting(RUNS_KEY, {month: int(runs.get(month, 0)) + 1})

    # ------------------------------------------------------------------ messages
    def _say(self, method: str, *args: Any) -> None:
        if self.notifier is not None:
            try:
                getattr(self.notifier, method)(*args)
            except Exception:
                pass

    def digest_add(self, name: str, text: str, now: datetime | None = None) -> None:
        d = self.store.get_setting(DIGEST_KEY)
        d = d if isinstance(d, list) else []
        d.append({"at": _iso(now or self.clock()), "app": name, "text": text[:400]})
        self.store.set_setting(DIGEST_KEY, d[-100:])

    def send_digest(self, now: datetime | None = None) -> bool:
        """Once a day from 08:00 (Berlin), when something happened."""
        now = now or self.clock()
        local = now.astimezone(TZ)
        st = self.store.get_setting(DB_STATE_KEY) or {}
        if local.hour < DIGEST_HOUR or st.get("_digest_day") == local.date().isoformat():
            return False
        entries = self.store.get_setting(DIGEST_KEY)
        st["_digest_day"] = local.date().isoformat()
        self.store.set_setting(DB_STATE_KEY, st)
        if not isinstance(entries, list) or not entries:
            return False
        self._say("pilot_digest", entries)
        self.store.set_setting(DIGEST_KEY, [])
        return True

    # ------------------------------------------------------------------ an outage
    def _log(self, p: dict[str, Any], now: datetime, text: str) -> None:
        p.setdefault("log", []).append({"at": _iso(now), "text": text})

    def _start_job(self, app: dict[str, Any], p: dict[str, Any], now: datetime, workflow: str, inputs: dict[str, str]) -> bool:
        if workflow == REPAIR and self.ai_runs(now) >= self.settings()["ai_cap"]:
            self._log(p, now, "Aylık Claude sınırı doldu; yapay zekâ çalıştırılmadı.")
            return False
        rid = secrets.token_hex(8)
        if not self.gh.dispatch(app["repair_repo"], workflow, rid, inputs):
            self._log(p, now, f"GitHub işi başlatılamadı ({workflow}).")
            return False
        if workflow == REPAIR:
            self._count_ai(now)
        p.update(job=workflow, rid=rid, job_at=_iso(now))
        return True

    def start(self, app: dict[str, Any], st: dict[str, Any], now: datetime, reason: str) -> bool:
        """The site just went down (two failed checks). Returns True when the autopilot took over."""
        if not self.enabled(app) or st.get("pilot"):
            return bool(st.get("pilot"))
        p: dict[str, Any] = {"since": _iso(now), "reason": reason, "alerted": False, "log": []}
        st["pilot"] = p
        if reason == "http_503":  # /health: the database does not answer -> first aid there, not a rollback
            self._log(p, now, "Veritabanı cevap vermiyor; takılmış bağlantılar kapatılıyor.")
            if self._start_job(app, p, now, FIRST_AID, {"action": "stuck"}):
                p["phase"] = "first_aid"
                return True
        else:
            self._log(p, now, "Site çalışmıyor; son yüklemeden önceki sürüme dönülüyor.")
            if self._start_job(app, p, now, ROLLBACK, {}):
                p["phase"] = "rollback"
                return True
        self._to_repair(app, p, now, reason)
        return True

    def _to_repair(self, app: dict[str, Any], p: dict[str, Any], now: datetime, reason: str) -> None:
        if self._start_job(app, p, now, REPAIR, {"reason": reason[:200]}):
            p["phase"] = "repair"
            self._log(p, now, "Claude sebebi araştırıyor.")
        else:
            p["phase"] = "stuck"

    def advance(self, app: dict[str, Any], st: dict[str, Any], now: datetime, up: bool) -> None:
        """Once a minute while an incident is open."""
        p = st.get("pilot")
        if not p:
            return
        repo, phase = app["repair_repo"], p.get("phase")
        if phase in ("rollback", "first_aid", "repair") and p.get("rid"):
            try:
                rep = self.gh.report(repo, p["job"], p["rid"])
            except (httpx.HTTPError, ValueError, KeyError, zipfile.BadZipFile):
                rep = None
            if rep is None and now - _parse(p["job_at"]) > JOB_TIMEOUT[p["job"]]:
                rep = {"status": "timeout"}
            if rep is not None:
                p.pop("rid", None)
                getattr(self, "_after_" + {"rollback": "rollback", "first_aid": "first_aid", "repair": "repair"}[phase])(app, p, now, up, rep)
        elif phase == "deploying":
            self._watch_deploy(app, p, now, up)
        if p.get("phase") == "waiting_owner" and up:
            # The site works (e.g. after the rollback); the fix waits for the owner without holding the incident open.
            st["pilot_wait"] = {k: p.get(k) for k in ("branch", "why", "run_url")} | {"at": _iso(now)}
            p["phase"] = "done"
        if p.get("phase") == "done":
            self._finish(app, st, now)
            return
        # Still down a quarter of an hour after it started, or nothing more to try: now the owner hears it.
        if not up and not p.get("alerted") and (now - _parse(p["since"]) >= ALERT_AFTER or p.get("phase") == "stuck"):
            p["alerted"] = True
            self._say("pilot_alert", app.get("name", ""), [x["text"] for x in p["log"]], app.get("links") or [])
        if up and p.get("phase") == "stuck":
            p["phase"] = "done"
            self._log(p, now, "Site kendiliğinden düzeldi.")
            self._finish(app, st, now)

    def _after_rollback(self, app, p, now, up, rep) -> None:
        if rep.get("status") == "rolled_back":
            p["rolled_back"] = True
            self._log(p, now, "Önceki sürüme dönüldü" + (", site çalışıyor." if rep.get("healthy") else ", site hâlâ çalışmıyor."))
            # The faulty code is still on main: Claude fixes it there, otherwise the next deployment brings it back.
            self._to_repair(app, p, now, "rolled_back: " + str(p.get("reason") or ""))
            return
        why = {"no_recent_deploy": "son 6 saatte yükleme yok", "already_rolled_back": "zaten geri dönülmüş"}.get(str(rep.get("reason")), str(rep.get("reason") or rep.get("status")))
        self._log(p, now, f"Geri dönüş yapılmadı ({why}).")
        self._to_repair(app, p, now, str(p.get("reason") or "down"))

    def _after_first_aid(self, app, p, now, up, rep) -> None:
        n = int(rep.get("terminated") or 0) + int(rep.get("cancelled") or 0)
        self._log(p, now, f"Veritabanı ilk yardımı: {n} takılmış bağlantı kapatıldı." if rep.get("status") == "done"
                  else "Veritabanı ilk yardımı yapılamadı.")
        if up:
            p["phase"] = "done"
            self._log(p, now, "Site yeniden çalışıyor.")
        else:
            self._to_repair(app, p, now, str(p.get("reason") or "down"))

    def _after_repair(self, app, p, now, up, rep) -> None:
        status, branch = rep.get("status"), rep.get("branch")
        summary = str(rep.get("summary") or "").strip()[:300]
        if summary:
            self._log(p, now, "Claude: " + summary)
        if status == "fixed" and branch:
            files = None
            try:
                files = self.gh.compare(app["repair_repo"], branch)
            except httpx.HTTPError:
                pass
            ok, why = guardrails(files or [])
            if ok and self._merges_today(app, now) >= MAX_MERGES_PER_DAY:
                ok, why = False, "daily_limit"
            if ok:
                sha = self.gh.merge(app["repair_repo"], branch, f"Autopilot: {branch} (BONELIA AI, tests passed)")
                if sha:
                    p.update(phase="deploying", merge_sha=sha, merged_at=_iso(now), branch=branch)
                    self._count_merge(app, now)
                    self._log(p, now, f"Düzeltme sınırların içinde; canlıya alınıyor ({branch}).")
                    return
                why = "merge_failed"
            p.update(phase="waiting_owner", branch=branch, why=why, run_url=rep.get("run_url"))
            self._log(p, now, f"Düzeltme hazır ama onayını bekliyor ({branch}).")
            self._say("pilot_waiting", app.get("name", ""), branch, why, str(rep.get("run_url") or ""))
            return
        if up:
            p["phase"] = "done"
            self._log(p, now, "Site çalışıyor; kodda değişiklik gerekmedi." if status != "fixed" else "Site çalışıyor.")
        else:
            p["phase"] = "stuck"
            self._log(p, now, "Claude bir düzeltme bulamadı.")

    def _watch_deploy(self, app, p, now, up) -> None:
        try:
            state = self.gh.deploy_state(app["repair_repo"], p["merge_sha"])
        except httpx.HTTPError:
            state = None
        if state is None:
            if now - _parse(p["merged_at"]) > DEPLOY_TIMEOUT:
                p["phase"] = "stuck"
                self._log(p, now, "Yükleme 40 dakikada bitmedi.")
            return
        if state == "success" and up:
            p["phase"] = "done"
            self._log(p, now, "Düzeltme canlıda, site çalışıyor.")
            return
        p.setdefault("deployed_at", _iso(now))
        if state == "failure" or now - _parse(p["deployed_at"]) >= UNHEALTHY_AFTER_DEPLOY:
            self._log(p, now, "Düzeltme canlıda işe yaramadı; önceki sürüme dönülüyor.")
            self._start_job(app, p, now, ROLLBACK, {})
            p.update(phase="stuck", alerted=False)
            p["since"] = _iso(now - ALERT_AFTER)  # tell the owner right away

    def approve(self, app: dict[str, Any], st: dict[str, Any]) -> str:
        """The owner's "Onayla" for a fix outside the limits."""
        p, now = st.get("pilot"), self.clock()
        if (not p or p.get("phase") != "waiting_owner") and st.get("pilot_wait") and not p:
            w = st.pop("pilot_wait")
            p = st["pilot"] = {"since": _iso(now), "reason": "approved", "alerted": True, "log": [], "phase": "waiting_owner", **w}
        if not p or p.get("phase") != "waiting_owner":
            return "nothing_waiting"
        sha = self.gh.merge(app["repair_repo"], p["branch"], f"Autopilot: {p['branch']} (approved by the owner)")
        if not sha:
            return "merge_failed"
        p.update(phase="deploying", merge_sha=sha, merged_at=_iso(now))
        self._log(p, now, "Sahibin onayıyla canlıya alınıyor.")
        return "merged"

    def _merges_today(self, app, now) -> int:
        m = (self.store.get_setting(DB_STATE_KEY) or {}).get("_merges", {})
        return int(m.get(f"{app['id']}|{now.date().isoformat()}", 0))

    def _count_merge(self, app, now) -> None:
        st = self.store.get_setting(DB_STATE_KEY) or {}
        key = f"{app['id']}|{now.date().isoformat()}"
        st["_merges"] = {key: int((st.get("_merges") or {}).get(key, 0)) + 1}
        self.store.set_setting(DB_STATE_KEY, st)

    def _finish(self, app, st, now) -> None:
        p = st.pop("pilot")
        lines = [x["text"] for x in p.get("log", [])]
        minutes = max(1, round((now - _parse(p["since"])).total_seconds() / 60))
        st["pilot_last"] = {"since": p["since"], "end": _iso(now), "minutes": minutes, "log": p.get("log", [])[-12:]}
        self.store.audit("server:autopilot", "autopilot.incident", {"app_id": app["id"], "minutes": minutes, "log": lines[-12:]})
        if p.get("alerted"):
            self._say("pilot_resolved", app.get("name", ""), minutes, lines)
        else:
            self.digest_add(app.get("name", ""), f"{minutes} dk kesinti, kendiliğinden çözüldü: " + " → ".join(lines[-4:]), now)

    # ------------------------------------------------------------------ database every 5 minutes (free)
    def db_check(self, app: dict[str, Any], stats: dict[str, Any] | None, now: datetime) -> str | None:
        """Decide on the five-minute database figures; returns the first-aid action started, if any."""
        st_all = self.store.get_setting(DB_STATE_KEY) or {}
        st = st_all.setdefault(app["id"], {})
        if stats is None:
            st["fail"] = int(st.get("fail", 0)) + 1
            self.store.set_setting(DB_STATE_KEY, st_all)
            return None
        st["fail"] = 0
        conn = stats["connections"] / stats["max_connections"] if stats.get("max_connections") else 0
        stuck = stats.get("stuck", 0) > 0 or stats.get("long_running", 0) > 0 or conn >= 0.85
        st["stuck_n"] = int(st.get("stuck_n", 0)) + 1 if stuck else 0
        st["full_n"] = int(st.get("full_n", 0)) + 1 if conn >= 0.9 else 0
        action = None
        last = st.get("aid_at")
        if st["stuck_n"] >= 2 and self.enabled(app) and (not last or now - _parse(last) >= timedelta(minutes=30)):
            p: dict[str, Any] = {"log": []}
            if self._start_job(app, p, now, FIRST_AID, {"action": "stuck"}):
                action, st["aid_at"] = "stuck", _iso(now)
                self.digest_add(app.get("name", ""), f"Veritabanında takılmış bağlantılar vardı (%{round(conn * 100)} dolu); kapatıldı.", now)
        if st["full_n"] == 3:  # 15 minutes at 90 %: first aid did not help
            self._say("pilot_alert", app.get("name", ""), [f"Veritabanı bağlantıları 15 dakikadır %{round(conn * 100)} dolu; ilk yardım yetmedi."], app.get("links") or [])
        self.store.set_setting(DB_STATE_KEY, st_all)
        return action

    def summary(self, states: dict[str, Any]) -> dict[str, Any]:
        s = self.settings()
        apps = []
        for a in self.store.get_setting("apps") or []:
            if not isinstance(a, dict) or not a.get("repair_repo"):
                continue
            st = states.get(a["id"]) or {}
            p = st.get("pilot")
            apps.append({"id": a["id"], "name": a.get("name"), "on": a["id"] not in s["off"],
                         "db_watch": a["id"] in (self.store.get_setting(DB_URLS_KEY) or {}),
                         "db_fail": int(((self.store.get_setting(DB_STATE_KEY) or {}).get(a["id"]) or {}).get("fail", 0)) >= 2,
                         "open": {k: p.get(k) for k in ("phase", "since", "branch", "why", "run_url")} | {"log": p.get("log", [])[-8:]} if p else None,
                         "waiting": st.get("pilot_wait"), "last": st.get("pilot_last")})
        return {"ai_cap": s["ai_cap"], "ai_runs": self.ai_runs(), "apps": apps,
                "digest": (self.store.get_setting(DIGEST_KEY) or [])[-20:]}


# ---------------------------------------------------------------------- the five-minute database figures
STATS_SQL = """select (select count(*) from pg_stat_activity) as connections,
 current_setting('max_connections')::int as max_connections,
 (select count(*) from pg_stat_activity where state = 'idle in transaction' and state_change < now() - interval '5 minutes'
    and pid <> pg_backend_pid()) as stuck,
 (select count(*) from pg_stat_activity where state = 'active' and query_start < now() - interval '2 minutes'
    and backend_type = 'client backend' and pid <> pg_backend_pid()) as long_running"""


CONNECT: Callable[..., Any] | None = None  # tests replace the database connection


def _connect(url: str, connect: Callable[..., Any] | None):
    u = urlsplit(url)
    if u.scheme not in ("postgres", "postgresql") or not u.hostname or not u.username:
        raise ValueError("invalid_url")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # sslmode=no-verify, like the GitHub job
    connect = connect or CONNECT
    if connect is None:
        import pg8000.dbapi as pg  # noqa: PLC0415 - optional at import time
        connect = pg.connect
    return connect(user=unquote(u.username), password=unquote(u.password or ""), host=u.hostname, port=u.port or 5432,
                   database=(u.path or "/postgres").lstrip("/") or "postgres", ssl_context=ctx, timeout=10,
                   application_name="bonelia-db-5min")


def db_login(url: str, connect: Callable[..., Any] | None = None) -> str:
    """'ok', 'auth' (the database refused this password) or 'unreachable' -- tried before the password goes to GitHub."""
    try:
        con = _connect(url, connect)
    except Exception as exc:
        text = str(exc).lower()
        return "auth" if "password authentication failed" in text or "28p01" in text else "unreachable"
    try:
        con.close()
    except Exception:
        pass
    return "ok"


def read_db_stats(url: str, connect: Callable[..., Any] | None = None) -> dict[str, Any] | None:
    """The monitor role's figures (pg_monitor: statistics only, never table data); None when unreachable."""
    try:
        con = _connect(url, connect)
    except Exception:
        return None
    try:
        cur = con.cursor()
        cur.execute("set statement_timeout = '10s'")
        cur.execute(STATS_SQL)
        row = cur.fetchone()
        return {"connections": int(row[0]), "max_connections": int(row[1]), "stuck": int(row[2]), "long_running": int(row[3])}
    except Exception:
        return None
    finally:
        try:
            con.close()
        except Exception:
            pass
