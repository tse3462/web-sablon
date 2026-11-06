"""AI repair of an own program (user request 06.11.2026).

When a program from "My apps" goes down, BONELIA AI starts the GitHub workflow ``auto-repair.yml`` in
that program's repository. There an AI looks for the cause; a code fix lands on its own branch, checked
with the program's tests. BONELIA then downloads the job's report and sends it to the owner's phone.
Nothing is deployed: going live stays the owner's decision.

The GitHub key needs only "Actions: read and write" on that one repository. It is stored here and
never shown again in the panel.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any

import httpx

TOKEN_KEY = "github_repair_token"
WORKFLOW = "auto-repair.yml"
ARTIFACT = "auto-repair-report"
API = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9_.](?:[A-Za-z0-9_.-]{0,99})$")
TOKEN_RE = re.compile(r"^(github_pat_|ghp_)[A-Za-z0-9_]{20,250}$")


def valid_repo(repo: str) -> bool:
    return bool(REPO_RE.match(repo)) and ".." not in repo


class GitHubRepair:
    def __init__(self, store, transport: httpx.BaseTransport | None = None):
        self.store, self.transport = store, transport

    def token(self) -> str | None:
        t = self.store.get_setting(TOKEN_KEY)
        return t if isinstance(t, str) and t else None

    def ready(self) -> bool:
        return self.token() is not None

    def _client(self) -> httpx.Client:
        # httpx drops the Authorization header when a redirect leaves api.github.com (artifact download).
        return httpx.Client(transport=self.transport, timeout=30.0, follow_redirects=True, headers={
            "authorization": f"Bearer {self.token()}", "accept": "application/vnd.github+json",
            "x-github-api-version": "2022-11-28", "user-agent": "BONELIA-AI-Repair/1.0"})

    def dispatch(self, repo: str, request_id: str, reason: str) -> bool:
        """Start the job; False when GitHub refuses (wrong key, missing workflow, no rights)."""
        if not self.ready() or not valid_repo(repo):
            return False
        try:
            with self._client() as c:
                r = c.post(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/dispatches",
                           json={"ref": "main", "inputs": {"request_id": request_id, "reason": (reason or "down")[:200]}})
            return r.status_code == 204
        except httpx.HTTPError:
            return False

    def result(self, repo: str, request_id: str) -> dict[str, Any] | None:
        """The job's report once it has finished; None while it is still queued or running."""
        with self._client() as c:
            r = c.get(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/runs",
                      params={"event": "workflow_dispatch", "per_page": 30})
            r.raise_for_status()
            run = next((x for x in r.json().get("workflow_runs", []) if x.get("display_title") == f"Auto repair {request_id}"), None)
            if run is None or run.get("status") != "completed":
                return None
            run_url = run.get("html_url")
            a = c.get(f"{API}/repos/{repo}/actions/runs/{int(run['id'])}/artifacts")
            a.raise_for_status()
            art = next((x for x in a.json().get("artifacts", []) if x.get("name") == ARTIFACT and not x.get("expired")), None)
            if art is None:
                return {"status": "run_failed", "conclusion": run.get("conclusion"), "run_url": run_url}
            z = c.get(art["archive_download_url"])
            z.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
            report = json.loads(zf.read("report.json").decode("utf-8"))
        if not isinstance(report, dict):
            return {"status": "run_failed", "conclusion": run.get("conclusion"), "run_url": run_url}
        out = {k: report.get(k) for k in ("status", "cause", "summary", "branch", "run_url")}
        out["summary"] = str(out.get("summary") or "")[:600]
        if not re.fullmatch(r"claude/auto-repair-\d{1,20}", str(out.get("branch") or "")):
            out["branch"] = None
        out["run_url"] = out.get("run_url") or run_url
        return out
