"""The background agent loop.

Every cycle (default 5 minutes):
1. read-only scan of the last hour (event log, services, metrics);
2. NEW important/check findings -> sent to the home server (AI analysis, alerts);
3. findings with a deterministic repair suggestion -> repair is requested; the SERVER
   decides (customer consent level, device scope, rate limits). Level-1 repairs run
   unattended; level-2 repairs are never self-confirmed by the agent (they are denied
   and appear as alerts for the technician);
4. every repair is independently verified and reported to the server's audit log.

Without a server connection nothing is repaired; findings are retried next cycle.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any, Callable

from ..contracts import Triage
from ..monitor.client import ServerClient, ServerError, ServerUnavailable
from ..monitor.repair_local import repair as run_repair
from ..monitor.scan import run_scan

log = logging.getLogger("bonelia.agent")
DENIED_RETRY_S = 6 * 3600


class AgentState:
    def __init__(self, path: Path):
        self.path = path
        try:
            self.data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("salt", secrets.token_hex(16))
        self.data.setdefault("seen", {})  # fingerprint -> last reported occurred_at (iso)
        self.data.setdefault("cycles", 0)
        self.data.setdefault("denied", {})  # repair key -> epoch seconds of the last denial

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        seen = self.data["seen"]
        if len(seen) > 2000:  # bounded state
            for k in sorted(seen, key=seen.get)[: len(seen) - 2000]:
                seen.pop(k, None)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)


class Agent:
    def __init__(self, client: ServerClient, state: AgentState, lang: str = "tr", executors=None,
                 scan: Callable[..., Any] = run_scan):
        self.client, self.state, self.lang, self.executors, self.scan = client, state, lang, executors, scan

    def cycle(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"new_findings": 0, "sent": False, "repairs": [], "offline": False}
        res = self.scan(mode="recent", salt=self.state.data["salt"], lang=self.lang)
        seen = self.state.data["seen"]
        def is_new(e) -> bool:
            if e.fingerprint not in seen:
                return True
            # log entries: new if a newer occurrence appeared; states (stopped service, full disk): report once
            from_log = any(ev.source.startswith(("windows_event_log", "logfile")) for ev in e.evidence)
            return from_log and seen[e.fingerprint] < e.occurred_at.isoformat()

        new = [e for e in res.events if e.triage != Triage.harmless and is_new(e)]
        summary["new_findings"] = len(new)
        try:
            if new:
                self.client.analyze(new[:25], res.system, False, self.lang)
                summary["sent"] = True
                for e in new[:25]:
                    seen[e.fingerprint] = e.occurred_at.isoformat()
            done: set[str] = set()
            denied = self.state.data["denied"]
            now = time.time()
            for e in res.events:
                if not e.repair_tool:
                    continue
                key = f"{e.repair_tool}|{json.dumps(e.repair_params, sort_keys=True)}"
                if key in done or now - denied.get(key, 0) < DENIED_RETRY_S:
                    continue  # not twice per cycle; denied repairs are not retried for a while (no alert spam)
                done.add(key)
                # technician_confirmed is always False: the agent never self-approves level-2 actions
                r = run_repair(self.client, e.repair_tool, dict(e.repair_params), False, self.executors)
                if r.get("outcome") == "denied":
                    denied[key] = now
                else:
                    denied.pop(key, None)
                summary["repairs"].append({k: r.get(k) for k in ("tool_id", "params", "outcome", "verified", "reasons")})
        except ServerUnavailable:
            summary["offline"] = True  # no repairs without the server; findings are retried next cycle
        except ServerError as exc:
            summary["error"] = f"{exc.status}:{exc.detail}"
        self.state.data["cycles"] += 1
        self.state.data["last_cycle"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), **summary}
        self.state.save()
        return summary

    def run_forever(self, interval_s: int = 300) -> None:
        while True:
            try:
                s = self.cycle()
                log.info("cycle: %s", s)
            except Exception as exc:  # the agent must never die on one bad cycle
                log.exception("cycle failed: %s", exc)
            time.sleep(max(60, interval_s))
