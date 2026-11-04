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
        self.data.setdefault("denied", {})
        self.data.setdefault("repaired", {})  # repair key + log occurrence -> epoch seconds  # repair key -> epoch seconds of the last denial

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
                 scan: Callable[..., Any] = run_scan, own_exe: Path | None = None, self_update: bool = False):
        self.client, self.state, self.lang, self.executors, self.scan = client, state, lang, executors, scan
        self.own_exe, self.self_update = own_exe, self_update

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
            repaired = self.state.data["repaired"]
            now = time.time()
            for k in [k for k, v in repaired.items() if now - v > 7 * 86400]:
                repaired.pop(k, None)
            for e in res.events:
                if not e.repair_tool:
                    continue
                key = f"{e.repair_tool}|{json.dumps(e.repair_params, sort_keys=True)}"
                # A log entry (e.g. "service crashed at 10:02") is repaired once per occurrence; a state
                # (e.g. "service is stopped") is repaired whenever it is still present.
                from_log = any(ev.source.startswith(("windows_event_log", "logfile")) for ev in e.evidence)
                occ_key = f"{key}|{e.occurred_at.isoformat()}" if from_log else None
                if key in done or now - denied.get(key, 0) < DENIED_RETRY_S or (occ_key and occ_key in repaired):
                    continue  # not twice per cycle; denied repairs are not retried for a while (no alert spam)
                done.add(key)
                # technician_confirmed is always False: the agent never claims a human click
                r = run_repair(self.client, e.repair_tool, dict(e.repair_params), False, self.executors)
                if r.get("outcome") == "denied":
                    denied[key] = now
                else:
                    denied.pop(key, None)
                    if occ_key:
                        repaired[occ_key] = now
                summary["repairs"].append({k: r.get(k) for k in ("tool_id", "params", "outcome", "verified", "reasons")})
        except ServerUnavailable:
            summary["offline"] = True  # no repairs without the server; findings are retried next cycle
        except ServerError as exc:
            summary["error"] = f"{exc.status}:{exc.detail}"
        self.state.data["cycles"] += 1
        self.state.data["last_cycle"] = {"at": time.strftime("%Y-%m-%dT%H:%M:%S"), **summary}
        self.state.save()
        if not summary["offline"]:
            if self.self_update and self.state.data["cycles"] % 3 == 1:  # every ~15 minutes
                try:
                    summary["update"] = self.check_update(self.own_exe)
                except (ServerUnavailable, ServerError, ValueError, OSError) as exc:
                    summary["update"] = f"error:{type(exc).__name__}"
            try:  # "alive" signal for the control panel, with a short summary of this cycle
                self.client.heartbeat({"cycles": self.state.data["cycles"], "new_findings": summary["new_findings"],
                                       "repairs": [f"{r.get('tool_id')}:{r.get('outcome')}" for r in summary["repairs"]],
                                       "important_open": sum(1 for e in res.events if e.triage == Triage.important)})
            except (ServerUnavailable, ServerError):
                pass
        return summary

    def check_update(self, own_exe: Path | None, apply: Callable[[Path], tuple[bool, str]] | None = None) -> dict[str, Any]:
        """Self-update: only a program signed by the pinned server key is installed."""
        import hashlib

        from ..security.crypto import load_public_key, verify_update

        if own_exe is None or not own_exe.is_file():
            return {"update": "not_applicable"}
        info = self.client.agent_update_info()
        if not info.get("available"):
            return {"update": "none_published"}
        own = hashlib.sha256(own_exe.read_bytes()).hexdigest()
        if info["sha256"] == own:
            return {"update": "up_to_date"}
        pub = load_public_key(self.client.creds.server_public_key_b64)
        verify_update(pub, info["sha256"], int(info["size"]), info["signature"])  # raises on forgery
        data = self.client.download_agent_update()
        if len(data) != int(info["size"]) or hashlib.sha256(data).hexdigest() != info["sha256"]:
            raise ValueError("downloaded update does not match the signed manifest")
        new = own_exe.with_name(own_exe.stem + ".new.exe")
        new.write_bytes(data)
        if apply is None:
            from .install import schedule_swap as apply
        ok, msg = apply(new)
        return {"update": "scheduled" if ok else "failed", "detail": msg[:200]}

    def run_forever(self, interval_s: int = 300) -> None:
        while True:
            try:
                s = self.cycle()
                log.info("cycle: %s", s)
            except Exception as exc:  # the agent must never die on one bad cycle
                log.exception("cycle failed: %s", exc)
            time.sleep(max(60, interval_s))
