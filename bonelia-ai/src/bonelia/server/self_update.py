"""BONELIA AI updates itself (user request 07.11.2026: "I may not be at the PC").

A hidden task runs ``BONELIA-Server-Guncelle.bat /auto`` every 30 minutes. It asks ``update-check`` here first:
update only when GitHub has newer code AND the BONELIA AI tests passed on GitHub for it. Local edits, a branch
that cannot fast-forward, red or still-running tests: nothing is touched. The script then updates, and when the
new server does not start it goes back to the old version. Its outcome is left in ``last_update.json``; the
server reports it once to Telegram.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

WORKFLOW = "bonelia-ai.yml"
NOTE = "last_update.json"
EXIT = {"update": 0, "none": 10, "wait": 11, "blocked": 12}
RESULTS = ("ok", "rolled_back", "merge_failed")
TRANSPORT: httpx.BaseTransport | None = None  # tests replace the network
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

Runner = Callable[[list[str]], tuple[int, str]]


def _git(cwd: Path) -> Runner:
    def run(args: list[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 1, str(exc)
        return p.returncode, (p.stdout or "").strip()
    return run


def github_repo(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def decide(git: Runner, transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    """What the hidden update task should do now. Runs ``git fetch``; never changes the working tree."""
    if git(["fetch", "--quiet"])[0] != 0:
        return {"action": "wait", "reason": "fetch_failed"}
    rc, head = git(["rev-parse", "HEAD"])
    rc2, up = git(["rev-parse", "@{u}"])
    if rc or rc2 or not SHA_RE.match(head) or not SHA_RE.match(up):
        return {"action": "blocked", "reason": "no_upstream"}
    if head == up:
        return {"action": "none"}
    if git(["merge-base", "--is-ancestor", "HEAD", "@{u}"])[0] != 0:
        return {"action": "blocked", "reason": "diverged", "to": up}
    if git(["status", "--porcelain", "--untracked-files=no"])[1]:
        return {"action": "blocked", "reason": "local_changes", "to": up}
    base = {"from": head, "to": up}
    # The tests that matter ran for the newest commit that changed this folder (a commit elsewhere in the
    # repository does not start them). Nothing here changed: nothing to test, nothing to fear.
    _, tested = git(["log", "-1", "--format=%H", "@{u}", "--", "."])
    if not SHA_RE.match(tested) or git(["merge-base", "--is-ancestor", tested, "HEAD"])[0] == 0:
        return {"action": "update", **base, "tests": "not_needed"}
    repo = github_repo(git(["remote", "get-url", "origin"])[1])
    if not repo:
        return {"action": "blocked", "reason": "not_github", **base}
    try:
        with httpx.Client(transport=transport or TRANSPORT, timeout=20,
                          headers={"Accept": "application/vnd.github+json", "User-Agent": "bonelia-ai-update"}) as c:
            r = c.get(f"https://api.github.com/repos/{repo}/actions/workflows/{WORKFLOW}/runs",
                      params={"head_sha": tested, "event": "push", "per_page": 10})
    except httpx.HTTPError:
        return {"action": "wait", "reason": "github_unreachable", **base}
    if r.status_code != 200:
        return {"action": "wait", "reason": f"github_{r.status_code}", **base}
    runs = [x for x in r.json().get("workflow_runs") or [] if x.get("head_sha") == tested]
    if any(x.get("conclusion") == "success" for x in runs):
        return {"action": "update", **base, "tests": "passed"}
    if not runs or any(x.get("status") != "completed" for x in runs):
        return {"action": "wait", "reason": "tests_running", **base}
    return {"action": "blocked", "reason": "tests_failed", **base, "tested": tested}


def write_note(data_dir: Path, note: dict[str, Any]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    note = {**note, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (data_dir / NOTE).write_text(json.dumps(note), encoding="utf-8")


def take_note(data_dir: Path) -> dict[str, Any] | None:
    """The update task's last outcome, once (the file is removed)."""
    p = data_dir / NOTE
    try:
        raw = json.loads(p.read_text(encoding="utf-8")[:4096])
    except (OSError, ValueError):
        return None
    finally:
        try:
            p.unlink()
        except OSError:
            pass
    if not isinstance(raw, dict):
        return None
    out = {k: str(raw.get(k) or "")[:80] for k in ("result", "reason", "from", "to", "at")}
    return out if out["result"] in (*RESULTS, "blocked") else None


def report(store, data_dir: Path, notifier) -> dict[str, Any] | None:
    note = take_note(data_dir)
    if note is None:
        return None
    store.audit("server:update", "server.self_update", note)
    if notifier is not None:
        notifier.self_update(note)
    return note
