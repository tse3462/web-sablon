"""Server side of the automatic rescue (user request 06.11.2026): the agent's report (memory, biggest
programs, frozen ones, what it did) is data from a PC and kept only in known fields; the owner's two
switches live in the settings and travel back with every heartbeat reply."""

from __future__ import annotations

import re
from typing import Any

SETTINGS_KEY = "rescue_settings"
DEFAULTS = {"hung": True, "memory": True}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.()+-]{0,75}\.[Ee][Xx][Ee]")
KINDS = ("hung", "memory", "manual")
OUTCOMES = ("executed_verified", "executed_unverified", "failed", "denied", "not_found")


def settings(store) -> dict[str, bool]:
    raw = store.get_setting(SETTINGS_KEY)
    raw = raw if isinstance(raw, dict) else {}
    return {k: raw.get(k, v) is not False for k, v in DEFAULTS.items()}


def _int(v: Any, hi: int = 2**32) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < hi else None


def _name(v: Any) -> str | None:
    return v if isinstance(v, str) and NAME.fullmatch(v) else None


def clean(raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    pct = raw.get("mem_pct")
    out: dict[str, Any] = {"mem_pct": round(float(pct), 1) if isinstance(pct, (int, float)) and not isinstance(pct, bool) and 0 <= pct <= 100 else None,
                           "total_mb": _int(raw.get("total_mb")), "top": [], "hung": [], "events": []}
    for t in (raw.get("top") or [])[:5]:
        if isinstance(t, dict) and _int(t.get("pid")) and _name(t.get("name")) and _int(t.get("mb")) is not None:
            out["top"].append({"pid": t["pid"], "name": t["name"], "mb": t["mb"]})
    for h in (raw.get("hung") or [])[:5]:
        if isinstance(h, dict) and _name(h.get("name")) and _int(h.get("secs")) is not None:
            out["hung"].append({"name": h["name"], "secs": h["secs"]})
    for e in (raw.get("events") or [])[-10:]:
        if isinstance(e, dict) and e.get("kind") in KINDS and _int(e.get("at")) and (_name(e.get("name")) or e.get("name") == ""):
            ev = {"at": e["at"], "kind": e["kind"], "name": e["name"],
                  "outcome": e.get("outcome") if e.get("outcome") in OUTCOMES else "failed"}
            for k in ("mb", "secs"):
                if _int(e.get(k)) is not None:
                    ev[k] = e[k]
            out["events"].append(ev)
    if isinstance(raw.get("request_done"), str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", raw["request_done"]):
        out["request_done"] = raw["request_done"]
    return out
