"""The background agent loop.

Every cycle (default 5 minutes):
1. read-only scan of the last hour (event log, services, metrics);
2. NEW important/check findings -> sent to the home server (AI analysis, alerts);
3. findings with a deterministic repair suggestion -> repair is requested; the SERVER
   decides (customer consent level, device scope, rate limits). Level-1 repairs run
   unattended; level-2 repairs are never self-confirmed by the agent (they are denied
   and appear as alerts for the technician);
4. routine housekeeping (by default a daily temp-file cleanup) runs on a schedule, not
   only when something is wrong -- this is the unattended "the computer cleans its own
   disk" behaviour. It goes through the same server consent gate as every other repair;
5. every repair is independently verified and reported to the server's audit log.

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
from ..collectors.remote import rustdesk_info, set_rustdesk_password
from ..security.vault import fingerprint, random_password, seal

log = logging.getLogger("bonelia.agent")
DENIED_RETRY_S = 6 * 3600
# Routine, unattended housekeeping that runs on a schedule rather than in response to a
# problem (what the owner means by "the computer cleans its own disk"). Only safe, level-1,
# idempotent tools belong here; each still goes through the server's consent gate, so it does
# nothing unless the customer has allowed repairs. Default: delete temp files older than 7 days.
MAINTENANCE_INTERVAL_S = 24 * 3600
MAINTENANCE_TOOLS: tuple[str, ...] = ("windows.clean_temp",)


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
        self.data.setdefault("last_maintenance", 0)  # epoch seconds of the last routine housekeeping pass

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
                 scan: Callable[..., Any] = run_scan, own_exe: Path | None = None, self_update: bool = False,
                 maintenance_interval_s: int = MAINTENANCE_INTERVAL_S, maintenance_tools: tuple[str, ...] = MAINTENANCE_TOOLS,
                 remote: Callable[[], dict | None] | None = None,
                 set_remote_password: Callable[[str], bool] | None = None):
        self.client, self.state, self.lang, self.executors, self.scan = client, state, lang, executors, scan
        self.own_exe, self.self_update = own_exe, self_update
        self.maintenance_interval_s, self.maintenance_tools = maintenance_interval_s, maintenance_tools
        self.remote = remote if remote is not None else rustdesk_info  # RustDesk ID for "connect" in the panel
        self._remote_cache: tuple[float, dict | None] | None = None
        self.set_remote_password = set_remote_password if set_remote_password is not None else set_rustdesk_password

    def remote_info(self) -> dict | None:
        """RustDesk state, read at most every 15 minutes (it starts a program)."""
        now = time.monotonic()
        if self._remote_cache is None or now - self._remote_cache[0] > 900:
            try:
                self._remote_cache = (now, self.remote())
            except Exception:  # remote access is a convenience; it must never stop monitoring
                self._remote_cache = (now, None)
        return self._remote_cache[1]

    def vault_password(self, remote: dict | None) -> tuple[dict | None, str | None]:
        """Password vault: once per vault (and per "new password" request) set a random RustDesk password
        and seal it to the owner's vault. Returns (sealed, marker); the marker is kept only after the
        server confirms it stored the box, otherwise the next cycle simply sets a fresh one."""
        v = self.state.data.get("vault") or {}
        pub = v.get("pub")
        if not pub or not remote or not remote.get("installed") or not remote.get("rustdesk_id"):
            return None, None
        marker = f"{fingerprint(pub)}|{v.get('rotate') or ''}"
        if self.state.data.get("rd_vaulted") == marker:
            return None, None
        failed = self.state.data.get("rd_vault_failed_at", 0)
        if failed and time.time() - failed < 3600:  # RustDesk refused: try again in an hour, not every cycle
            return None, None
        password = random_password()
        try:
            ok = self.set_remote_password(password)
        except Exception:
            ok = False
        if not ok:
            self.state.data["rd_vault_failed_at"] = time.time()
            return None, None
        self.state.data.pop("rd_vault_failed_at", None)
        sealed = {"box": seal(pub, {"password": password, "rustdesk_id": remote["rustdesk_id"]}),
                  "for": fingerprint(pub), "rotate": v.get("rotate")}
        return sealed, marker

    def cycle(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"new_findings": 0, "sent": False, "repairs": [], "offline": False}
        policy = self.state.data.get("policy") or {}  # settings from the panel, delivered with the heartbeat reply
        res = self.scan(mode="recent", salt=self.state.data["salt"], lang=self.lang, backup_policy=policy.get("backup"))
        seen = self.state.data["seen"]
        if "states" not in self.state.data:  # upgrade: states reported by an older version count as known
            self.state.data["states"] = list(seen)
        states_prev = set(self.state.data["states"])

        def from_log(e) -> bool:
            return any(ev.source.startswith(("windows_event_log", "logfile")) for ev in e.evidence)

        def is_new(e) -> bool:
            if from_log(e):  # log entries: new if unseen or a newer occurrence appeared
                return e.fingerprint not in seen or seen[e.fingerprint] < e.occurred_at.isoformat()
            # states (stopped service, failing disk, old backup): new whenever they (re)appear,
            # so a problem that was solved and comes back is reported again
            return e.fingerprint not in states_prev

        new = [e for e in res.events if e.triage != Triage.harmless and is_new(e)]
        states_now = {e.fingerprint for e in res.events if e.triage != Triage.harmless and not from_log(e)}
        reported: set[str] = set()
        summary["new_findings"] = len(new)
        try:
            if new:
                self.client.analyze(new[:25], res.system, False, self.lang)
                summary["sent"] = True
                for e in new[:25]:
                    seen[e.fingerprint] = e.occurred_at.isoformat()
                    reported.add(e.fingerprint)
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
            # Routine housekeeping on a schedule (e.g. daily temp-file cleanup), independent of any
            # problem. It runs through the same consent gate as every repair, so a customer who has
            # not allowed repairs simply sees it denied — never executed without consent.
            if self.maintenance_tools and now - self.state.data["last_maintenance"] >= self.maintenance_interval_s:
                ran_any = False
                for tool_id in self.maintenance_tools:
                    key = f"{tool_id}|{json.dumps({}, sort_keys=True)}"
                    if key in done:  # already handled this cycle by a finding (e.g. disk already 90% full)
                        ran_any = True
                        continue
                    done.add(key)
                    r = run_repair(self.client, tool_id, {}, False, self.executors)
                    ran_any = True
                    rec = {k: r.get(k) for k in ("tool_id", "params", "outcome", "verified", "reasons")}
                    rec["maintenance"] = True
                    summary["repairs"].append(rec)
                if ran_any:
                    self.state.data["last_maintenance"] = now
                    if any(r.get("maintenance") and "rate_limited" in (r.get("reasons") or []) for r in summary["repairs"]):
                        # hit the hourly safety limit (e.g. after restarts): try again in an hour, not tomorrow
                        self.state.data["last_maintenance"] = now - self.maintenance_interval_s + 3600
        except ServerUnavailable:
            summary["offline"] = True  # no repairs without the server; findings are retried next cycle
        except ServerError as exc:
            summary["error"] = f"{exc.status}:{exc.detail}"
        # remember active states: solved ones drop out (re-reported if they return); unsent new ones are retried
        self.state.data["states"] = sorted((states_prev & states_now) | (reported & states_now))
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
                status = {"cycles": self.state.data["cycles"], "new_findings": summary["new_findings"],
                          "repairs": [f"{r.get('tool_id')}:{r.get('outcome')}" for r in summary["repairs"]],
                          "important_open": sum(1 for e in res.events if e.triage == Triage.important)}
                remote = self.remote_info()
                sealed, marker = self.vault_password(remote)
                if remote:
                    status["remote"] = {**remote, "vault": sealed} if sealed else remote
                resp = self.client.heartbeat(status)
                if isinstance(resp, dict):
                    if marker and resp.get("vault_saved") is True:
                        self.state.data["rd_vaulted"] = marker
                    vault_info = resp.get("vault") if isinstance(resp.get("vault"), dict) else None
                    if vault_info != self.state.data.get("vault"):
                        self.state.data["vault"] = vault_info
                    self.state.save()
                if isinstance(resp, dict) and isinstance(resp.get("policy"), dict) and resp["policy"] != self.state.data.get("policy"):
                    self.state.data["policy"] = resp["policy"]  # used from the next cycle on
                    self.state.save()
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
