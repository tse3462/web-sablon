"""Automatic rescue of a stuck PC (user request 06.11.2026).

Runs every ~20 seconds inside the agent, between its 5-minute cycles:
* a program whose window has not answered for HUNG_AFTER_S is closed and opened again
  (``windows.restart_hung_app``) -- a window that hangs that long is almost never coming back;
* when the memory stays above MEM_HIGH_PCT for MEM_HIGH_FOR_S, the biggest program is asked to
  close like a click on its X (``windows.close_program``, never forced: a program with unsaved work
  asks to save and stays open) and is opened again, which gives back the memory it held;
* the owner can close a program from the panel (a request delivered with the heartbeat reply).

Every action goes through the server's repair gate like any other repair (consent level, rate
limits, audit log, Telegram). Windows' own programs, remote access and BONELIA itself are never
touched. This module only decides; probing and acting are passed in (tested without Windows).
"""

from __future__ import annotations

import time
from typing import Any, Callable

HUNG_AFTER_S = 180
MEM_HIGH_PCT = 92.0
MEM_HIGH_FOR_S = 600
MEM_MIN_MB = 800  # closing a smaller program would not help
SAME_APP_PAUSE_S = 2 * 3600  # a program closed for memory is not closed again for two hours
MAX_EVENTS = 10

# Lower-case process names that are never closed: Windows itself, the security center, remote access and
# BONELIA (on the owner's PC the agent runs as python.exe).
PROTECTED = frozenset({
    "system", "registry", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsaiso.exe", "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    "applicationframehost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe", "searchhost.exe", "searchapp.exe",
    "searchui.exe", "textinputhost.exe", "lockapp.exe", "logonui.exe", "conhost.exe", "runtimebroker.exe", "dllhost.exe",
    "securityhealthsystray.exe", "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe", "smartscreen.exe",
    "taskmgr.exe", "audiodg.exe", "spoolsv.exe", "wudfhost.exe", "userinit.exe", "consent.exe", "mmc.exe",
    "boneliaai-agent.exe", "boneliaai.exe", "python.exe", "pythonw.exe", "py.exe",
    "rustdesk.exe", "tailscale.exe", "tailscale-ipn.exe", "tailscaled.exe",
})


def is_protected(name: str) -> bool:
    n = str(name or "").strip().lower()
    return not n or n in PROTECTED or not n.endswith(".exe")


class Rescue:
    def __init__(self, state: dict[str, Any], probe: Callable[[], dict | None], act: Callable[[str, dict], dict],
                 clock: Callable[[], float] = time.time):
        """state: a dict kept by the agent between runs; probe: the PC's programs now; act: run a repair tool
        through the server gate and return its result ({"outcome": ...}); "offline" means not tried."""
        self.state, self.probe, self.act, self.clock = state, probe, act, clock
        for k, v in (("hung_since", {}), ("hung_done", {}), ("closed", {}), ("events", [])):
            state.setdefault(k, v)
        self.snap: dict | None = None
        self.changed = False

    def _event(self, kind: str, name: str, result: dict, **extra: Any) -> None:
        ev = {"at": int(self.clock()), "kind": kind, "name": name, "outcome": str(result.get("outcome") or "failed")[:30], **extra}
        self.state["events"] = (self.state["events"] + [ev])[-MAX_EVENTS:]
        self.changed = True

    def _do(self, tool: str, params: dict) -> dict | None:
        try:
            r = self.act(tool, dict(params))
        except Exception:  # an action must never stop the agent
            r = {"outcome": "failed"}
        return None if (r or {}).get("outcome") == "offline" else (r or {"outcome": "failed"})

    def tick(self, settings: dict | None = None, request: dict | None = None) -> None:
        settings = settings or {}
        self.changed = False
        try:
            snap = self.probe()
        except Exception:
            snap = None
        self.snap = snap
        if not isinstance(snap, dict):
            return
        now = self.clock()
        procs = [p for p in snap.get("procs") or [] if isinstance(p, dict) and isinstance(p.get("pid"), int)]

        # 1. programs that do not answer
        hung_since, hung_done = self.state["hung_since"], self.state["hung_done"]
        current = set()
        for p in procs:
            if not p.get("hung") or is_protected(p.get("name")):
                continue
            key = f"{p['pid']}:{p.get('started')}"
            current.add(key)
            since = hung_since.setdefault(key, now)
            if settings.get("hung", True) and now - since >= HUNG_AFTER_S and key not in hung_done:
                r = self._do("windows.restart_hung_app", {"pid": p["pid"], "name": p["name"]})
                if r is not None:
                    hung_done[key] = now
                    self._event("hung", p["name"], r, secs=int(now - since))
        for k in [k for k in hung_since if k not in current]:
            hung_since.pop(k)
        for k in [k for k, v in hung_done.items() if now - v > 3600]:
            hung_done.pop(k)

        # 2. a close request from the panel (once per request)
        if isinstance(request, dict) and request.get("id") and request["id"] != self.state.get("request_done"):
            name = str(request.get("name") or "")
            target = next((p for p in procs if p["pid"] == request.get("pid") and str(p.get("name")).lower() == name.lower()), None)
            if target is None or is_protected(name):
                self.state["request_done"] = request["id"]
                self._event("manual", name, {"outcome": "not_found"})
            else:
                r = self._do("windows.close_program", {"pid": target["pid"], "name": target["name"], "restart": request.get("restart") is True})
                if r is not None:
                    self.state["request_done"] = request["id"]
                    self.state["closed"][target["name"].lower()] = now
                    self._event("manual", target["name"], r, mb=int(target.get("mb") or 0))

        # 3. memory full for a while: the biggest program that can help
        closed = self.state["closed"]
        for k in [k for k, v in closed.items() if now - v > SAME_APP_PAUSE_S]:
            closed.pop(k)
        pct = snap.get("mem_pct")
        if isinstance(pct, (int, float)) and pct >= MEM_HIGH_PCT:
            since = self.state.setdefault("mem_high_since", now)
            if settings.get("memory", True) and now - since >= MEM_HIGH_FOR_S:
                cands = [p for p in procs if not is_protected(p.get("name")) and not p.get("hung")
                         and int(p.get("mb") or 0) >= MEM_MIN_MB and str(p["name"]).lower() not in closed]
                if cands:
                    c = max(cands, key=lambda p: int(p.get("mb") or 0))
                    r = self._do("windows.close_program", {"pid": c["pid"], "name": c["name"], "restart": True})
                    if r is not None:
                        closed[c["name"].lower()] = now
                        self.state["mem_high_since"] = now  # give Windows ten minutes before the next step
                        self._event("memory", c["name"], r, mb=int(c.get("mb") or 0), pct=round(float(pct), 1))
        else:
            self.state.pop("mem_high_since", None)

    def report(self) -> dict[str, Any]:
        """For the panel (sent with the heartbeat): memory now, the biggest programs, frozen ones, recent actions."""
        snap = self.snap if isinstance(self.snap, dict) else {}
        procs = [p for p in snap.get("procs") or [] if isinstance(p, dict) and not is_protected(p.get("name"))]
        now = self.clock()
        top = sorted(procs, key=lambda p: int(p.get("mb") or 0), reverse=True)[:5]
        hung = [{"name": p["name"], "secs": int(now - self.state["hung_since"].get(f"{p['pid']}:{p.get('started')}", now))}
                for p in procs if p.get("hung")]
        return {"mem_pct": snap.get("mem_pct"), "total_mb": snap.get("total_mb"),
                "top": [{"pid": p["pid"], "name": p["name"], "mb": int(p.get("mb") or 0)} for p in top],
                "hung": hung[:5], "events": list(self.state["events"]), "request_done": self.state.get("request_done")}
