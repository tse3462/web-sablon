"""Weekly database check of the own programs (user request 07.11.2026).

Every program from "Programlar" with a GitHub repository can carry the job ``db-saglik.yml``: once a week (and when
the owner taps "Şimdi kontrol et") it reads the database's statistics with a monitor role that cannot see table
data, and Claude explains the result in plain Turkish. BONELIA AI picks up each new report, keeps the latest one
per program for the panel and sends it to Telegram. Nothing here changes a database.
"""

from __future__ import annotations

import io
import json
import secrets
import zipfile
from typing import Any

import httpx

from .repair import API, GitHubRepair, valid_repo

WORKFLOW = "db-saglik.yml"
ARTIFACT = "db-saglik-report"
SETTINGS_KEY = "db_health"
STATUSES = ("ok", "info", "warn", "crit", "no_secret", "failed")
LEVELS = ("ok", "info", "warn", "crit")
TRANSPORT: httpx.BaseTransport | None = None  # tests replace the network


def clean_report(raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    findings = []
    for f in (raw.get("findings") or [])[:20]:
        if isinstance(f, dict) and f.get("level") in LEVELS and isinstance(f.get("text"), str):
            findings.append({"level": f["level"], "code": str(f.get("code") or "")[:30], "text": f["text"][:300]})
    db_mb = raw.get("db_mb")
    return {"status": raw.get("status") if raw.get("status") in STATUSES else "failed", "findings": findings,
            "db_mb": float(db_mb) if isinstance(db_mb, (int, float)) and not isinstance(db_mb, bool) else None,
            "summary": str(raw.get("summary") or "")[:1500], "run_url": str(raw.get("run_url") or "")[:300]}


class DbHealthWatch:
    def __init__(self, store, github: GitHubRepair | None = None, notifier: Any = None):
        self.store = store
        self.github = github or GitHubRepair(store, TRANSPORT)
        self.notifier = notifier

    def programs(self) -> list[dict[str, Any]]:
        return [a for a in self.store.get_setting("apps") or []
                if isinstance(a, dict) and a.get("repair_repo") and valid_repo(str(a["repair_repo"]))]

    def reports(self) -> dict[str, Any]:
        r = self.store.get_setting(SETTINGS_KEY)
        return r if isinstance(r, dict) else {}

    def _latest(self, repo: str) -> tuple[int, str, dict[str, Any]] | None:
        with self.github._client() as c:
            r = c.get(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/runs", params={"status": "completed", "per_page": 5})
            if r.status_code == 404:
                return None  # the job is not in this repository (yet)
            r.raise_for_status()
            runs = r.json().get("workflow_runs") or []
            if not runs:
                return None
            run = max(runs, key=lambda x: int(x.get("id") or 0))
            a = c.get(f"{API}/repos/{repo}/actions/runs/{int(run['id'])}/artifacts")
            a.raise_for_status()
            art = next((x for x in a.json().get("artifacts", []) if x.get("name") == ARTIFACT and not x.get("expired")), None)
            if art is None:
                return int(run["id"]), str(run.get("updated_at") or ""), {"status": "failed", "run_url": run.get("html_url")}
            z = c.get(art["archive_download_url"])
            z.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            rep = json.loads(zf.read("report.json").decode("utf-8"))
        return int(run["id"]), str(run.get("updated_at") or ""), rep

    def poll(self) -> list[str]:
        """Fetch new reports; returns the program ids that got one."""
        if not self.github.ready():
            return []
        reports, fresh = self.reports(), []
        for app in self.programs():
            try:
                got = self._latest(app["repair_repo"])
            except (httpx.HTTPError, ValueError, KeyError, zipfile.BadZipFile):
                continue
            if got is None:
                continue
            run_id, at, raw = got
            if (reports.get(app["id"]) or {}).get("run_id") == run_id:
                continue
            rep = {**clean_report(raw), "run_id": run_id, "at": at, "name": app.get("name") or app["repair_repo"]}
            reports[app["id"]] = rep
            fresh.append(app["id"])
            if self.notifier is not None:
                try:
                    self.notifier.db_health(rep["name"], rep)
                except Exception:
                    pass
        if fresh:
            self.store.set_setting(SETTINGS_KEY, reports)
        return fresh

    def run_now(self, app_id: str) -> str:
        app = next((a for a in self.programs() if a.get("id") == app_id), None)
        if app is None:
            return "unknown_app"
        if not self.github.ready():
            return "no_token"
        try:
            with self.github._client() as c:
                r = c.post(f"{API}/repos/{app['repair_repo']}/actions/workflows/{WORKFLOW}/dispatches",
                           json={"ref": "main", "inputs": {"request_id": secrets.token_hex(6)}})
        except httpx.HTTPError:
            return "refused"
        return "started" if r.status_code == 204 else "refused"
