"""The "Geliştir" box (user request 07.11.2026).

The owner writes (or dictates on the phone) a wish for one of his programs. BONELIA AI starts the GitHub job
``claude-gelistir.yml`` in that program's repository: Claude makes the change, the program's tests run, and the
result is saved on its own branch ``claude/gelistir-<run>``. The report comes back to the panel and Telegram.
Only the owner's "Onayla" merges that branch into the program's working branch -- for BONELIA AI itself its
development branch (then BONELIA-Server-Guncelle brings it to this PC), for a program like the reservation app
its main branch, which is the same as going live there.

The GitHub key is the one stored for AI repair; it needs "Actions" and "Contents: read and write" on the repository.
"""

from __future__ import annotations

import re
import secrets
from datetime import timedelta
from typing import Any

import httpx

from ..contracts import utcnow
from .repair import API, GitHubRepair, valid_repo

WORKFLOW = "claude-gelistir.yml"
ARTIFACT = "gelistir-report"
SETTINGS_KEY = "develop_requests"
MAX_KEEP = 30
MAX_TEXT = 2000
GIVE_UP = timedelta(minutes=120)
BRANCH_RE = re.compile(r"^claude/gelistir-\d{1,20}$")
BONELIA_TARGET = {"id": "bonelia-ai", "name": "BONELIA AI", "repo": "tse3462/web-sablon",
                  "base": "claude/bonelia-ai-architecture-z57jp0", "live": False}
TRANSPORT: httpx.BaseTransport | None = None  # tests replace the network


class GitHubDevelop(GitHubRepair):
    def dispatch_wish(self, repo: str, base: str, request_id: str, text: str) -> bool:
        if not self.ready() or not valid_repo(repo):
            return False
        try:
            with self._client() as c:
                r = c.post(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/dispatches",
                           json={"ref": base, "inputs": {"request_id": request_id, "request": text}})
            return r.status_code == 204
        except httpx.HTTPError:
            return False

    def wish_result(self, repo: str, request_id: str) -> dict[str, Any] | None:
        import io
        import json
        import zipfile

        with self._client() as c:
            r = c.get(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/runs", params={"event": "workflow_dispatch", "per_page": 30})
            r.raise_for_status()
            run = next((x for x in r.json().get("workflow_runs", []) if x.get("display_title") == f"Gelistir {request_id}"), None)
            if run is None or run.get("status") != "completed":
                return None
            a = c.get(f"{API}/repos/{repo}/actions/runs/{int(run['id'])}/artifacts")
            a.raise_for_status()
            art = next((x for x in a.json().get("artifacts", []) if x.get("name") == ARTIFACT and not x.get("expired")), None)
            if art is None:
                return {"status": "failed", "summary": "", "run_url": run.get("html_url")}
            z = c.get(art["archive_download_url"])
            z.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            rep = json.loads(zf.read("report.json").decode("utf-8"))
        rep = rep if isinstance(rep, dict) else {}
        status = rep.get("status") if rep.get("status") in ("ready", "no_change", "tests_failed", "no_key", "failed") else "failed"
        branch = str(rep.get("branch") or "")
        return {"status": status, "summary": str(rep.get("summary") or "")[:1500],
                "branch": branch if BRANCH_RE.match(branch) else None,
                "tests": rep.get("tests") if rep.get("tests") in ("passed", "failed", "none") else "none",
                "run_url": str(rep.get("run_url") or run.get("html_url") or "")[:300]}

    def merge(self, repo: str, base: str, head: str, message: str) -> bool:
        try:
            with self._client() as c:
                r = c.post(f"{API}/repos/{repo}/merges", json={"base": base, "head": head, "commit_message": message})
            return r.status_code in (201, 204)
        except httpx.HTTPError:
            return False


class DevelopDesk:
    def __init__(self, store, github: GitHubDevelop | None = None, notifier: Any = None):
        self.store = store
        self.github = github or GitHubDevelop(store, TRANSPORT)
        self.notifier = notifier

    # -- what can be developed: BONELIA AI itself and every program with a GitHub repository
    def targets(self) -> list[dict[str, Any]]:
        out = [dict(BONELIA_TARGET)]
        for a in self.store.get_setting("apps") or []:
            if isinstance(a, dict) and a.get("repair_repo") and valid_repo(str(a["repair_repo"])):
                out.append({"id": a["id"], "name": a.get("name") or a["repair_repo"], "repo": a["repair_repo"], "base": "main", "live": True})
        return out

    def requests(self) -> list[dict[str, Any]]:
        r = self.store.get_setting(SETTINGS_KEY)
        return r if isinstance(r, list) else []

    def _save(self, reqs: list[dict[str, Any]]) -> None:
        self.store.set_setting(SETTINGS_KEY, reqs[:MAX_KEEP])

    def submit(self, target_id: str, text: str) -> dict[str, Any] | str:
        text = (text or "").strip()
        if not text or len(text) > MAX_TEXT:
            return "invalid_request"
        target = next((t for t in self.targets() if t["id"] == target_id), None)
        if target is None:
            return "unknown_target"
        if not self.github.ready():
            return "no_token"
        rid = secrets.token_hex(6)
        if not self.github.dispatch_wish(target["repo"], target["base"], rid, text):
            return "refused"
        req = {"id": rid, "target": target["id"], "name": target["name"], "repo": target["repo"], "base": target["base"],
               "live": target["live"], "text": text, "at": utcnow().isoformat(), "state": "running", "report": None}
        self._save([req] + self.requests())
        self.store.audit("admin:dashboard", "develop.requested", {"target": target["id"], "id": rid, "text": text[:200]})
        return req

    def poll(self) -> None:
        reqs, changed = self.requests(), False
        for r in reqs:
            if r.get("state") != "running":
                continue
            try:
                res = self.github.wish_result(r["repo"], r["id"])
            except (httpx.HTTPError, ValueError, KeyError):
                res = None
            if res is None:
                from datetime import datetime
                if utcnow() - datetime.fromisoformat(r["at"]) > GIVE_UP:
                    r.update(state="failed", report={"status": "failed", "summary": "", "branch": None, "tests": "none", "run_url": ""})
                    changed = True
                continue
            r["report"] = res
            r["state"] = res["status"] if not (res["status"] == "ready" and not res.get("branch")) else "failed"
            changed = True
            if self.notifier is not None:
                try:
                    self.notifier.develop_result(r["name"], r)
                except Exception:
                    pass
        if changed:
            self._save(reqs)

    def approve(self, rid: str) -> str:
        reqs = self.requests()
        r = next((x for x in reqs if x.get("id") == rid), None)
        if r is None:
            return "unknown"
        rep = r.get("report") or {}
        if r.get("state") != "ready" or rep.get("tests") != "passed" or not BRANCH_RE.match(str(rep.get("branch") or "")):
            return "not_ready"
        if not self.github.merge(r["repo"], r["base"], rep["branch"], f"Geliştir: {r['text'][:72]} (onaylandı)"):
            return "merge_failed"
        r["state"] = "merged"
        r["merged_at"] = utcnow().isoformat()
        self._save(reqs)
        self.store.audit("admin:dashboard", "develop.approved", {"target": r["target"], "id": rid, "branch": rep["branch"]})
        return "merged"
