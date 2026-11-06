"""Disk reports from the agents (user request 06.11.2026): latest report per PC, daily free space for the
trend, and the alerts "almost full" (under 15 % free) and "big drop" (over 10 GB less within a week)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ..contracts import utcnow

GB = 1024 ** 3
LOW_SHARE = 0.15
DROP_BYTES = 10 * GB
DROP_DAYS = 7
REASONS = {"old_backup", "duplicate", "old_download"}
SAFE_KEYS = {"temp", "recycle", "pip_cache", "npm_cache", "browser_cache"}
SCHEMA = """
create table if not exists disk_reports (device_id text primary key, at text not null, report text not null);
create table if not exists disk_progress (device_id text primary key, request text not null, pct integer not null, at text not null);
create table if not exists disk_history (device_id text not null, day text not null, free integer not null,
  total integer not null, primary key (device_id, day));
"""


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _str(v: Any, n: int) -> str | None:
    return v[:n] if isinstance(v, str) and v else None


def _node(x: Any, depth: int) -> dict[str, Any] | None:
    """A folder of the open-up view: path, size, whether the PC allows deleting it, why not, sub-folders."""
    if not isinstance(x, dict) or not _str(x.get("path"), 500) or _int(x.get("bytes")) is None:
        return None
    nid = x.get("id") if isinstance(x.get("id"), str) and re.fullmatch(r"[0-9a-f]{16}", x["id"]) else None
    kids = [k for k in (_node(c, depth - 1) for c in (x.get("children") or [])[:8]) if k] if depth > 0 else []
    return {"id": nid, "path": x["path"][:500], "bytes": x["bytes"], "deletable": bool(nid) and x.get("deletable") is True,
            "note": (x.get("note") if isinstance(x.get("note"), str) else "")[:20], "children": kids,
            "last_write": _int(x.get("last_write")) or 0, "use": x.get("use") if x.get("use") in ("in_use", "unused") else "",
            "backup": _str(x.get("backup"), 500)}


def tree_nodes(rep: dict[str, Any]):
    """Every folder node of a stored report (largest folders and the categories' parts)."""
    stack = list(rep.get("largest") or []) + [p for c in rep.get("categories") or [] for p in c.get("parts") or []]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.get("children") or [])


def clean_report(raw: Any) -> dict[str, Any]:
    """Keep only the known fields, in bounded size: a report is data from a PC, not trusted input."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {"at": _int(raw.get("at")) or 0, "partial": raw.get("partial") is True,
                           "drives": [], "categories": [], "largest": [], "suggestions": []}
    for d in (raw.get("drives") or [])[:5]:
        if isinstance(d, dict) and _str(d.get("name"), 40) and _int(d.get("total")) is not None and _int(d.get("free")) is not None:
            out["drives"].append({"name": d["name"][:40], "total": d["total"], "free": d["free"]})
    for c in (raw.get("categories") or [])[:20]:
        if isinstance(c, dict) and _str(c.get("key"), 40) and c.get("kind") in ("safe", "info") and _int(c.get("bytes")) is not None:
            parts = [n for n in (_node(x, 3) for x in (c.get("parts") or [])[:8]) if n]
            out["categories"].append({"key": c["key"][:40], "kind": c["kind"], "bytes": c["bytes"], "parts": parts})
    out["largest"] = [n for n in (_node(f, 3) for f in (raw.get("largest") or [])[:20]) if n]
    for s in (raw.get("suggestions") or [])[:400]:
        if not isinstance(s, dict) or not (isinstance(s.get("id"), str) and re.fullmatch(r"[0-9a-f]{16}", s["id"])):
            continue
        if _str(s.get("path"), 500) and _int(s.get("bytes")) and _int(s.get("mtime")) is not None and s.get("reason") in REASONS:
            out["suggestions"].append({"id": s["id"], "path": s["path"][:500], "bytes": s["bytes"], "mtime": s["mtime"],
                                       "reason": s["reason"], "group": (s.get("group") if isinstance(s.get("group"), str) else "")[:80]})
    for a in (raw.get("advice") or [])[:20]:
        if (isinstance(a, dict) and isinstance(a.get("id"), str) and re.fullmatch(r"[0-9a-f]{16}", a["id"]) and _str(a.get("path"), 500)
                and _int(a.get("bytes")) and a.get("why") in ("has_backup", "unused", "docker_unused")):
            out.setdefault("advice", []).append({"id": a["id"], "path": a["path"][:500], "bytes": a["bytes"], "why": a["why"],
                                                 "days": _int(a.get("days")) or 0, "backup": _str(a.get("backup"), 500),
                                                 "last_write": _int(a.get("last_write")) or 0})
    for d in (raw.get("backup_drives") or [])[:6]:
        if isinstance(d, dict) and _str(d.get("name"), 40) and _int(d.get("free")) is not None and _int(d.get("total")) is not None:
            out.setdefault("backup_drives", []).append({"name": d["name"][:40], "free": d["free"], "total": d["total"],
                                                        "label": (d.get("label") if isinstance(d.get("label"), str) else "")[:40]})
    res = raw.get("cleanup_result")
    if isinstance(res, dict) and _str(res.get("id"), 40):
        out["cleanup_result"] = {"id": res["id"][:40], "freed": _int(res.get("freed")) or 0,
                                 "deleted": sum(1 for f in (res.get("files") or []) + (res.get("folders") or []) + (res.get("moves") or [])
                                                if isinstance(f, dict) and f.get("status") in ("deleted", "moved")),
                                 "skipped": sum(1 for f in (res.get("files") or []) + (res.get("folders") or []) + (res.get("moves") or [])
                                                if isinstance(f, dict) and f.get("status") not in ("deleted", "moved")),
                                 "moved": [{"path": _str(m.get("path"), 500), "dest": _str(m.get("dest"), 500), "status": _str(m.get("status"), 20)}
                                           for m in (res.get("moves") or [])[:20] if isinstance(m, dict)],
                                 "error": _str(res.get("error"), 80)}
    if _str(raw.get("scan_request"), 40):
        out["scan_request"] = raw["scan_request"][:40]
    return out


class DiskStore:
    def __init__(self, store):
        self.store = store
        with store._lock:
            store._db.executescript(SCHEMA)

    def accept(self, device_id: str, raw: Any, now: datetime | None = None) -> list[tuple]:
        """Store the report; return the alerts it calls for: ("disk_low", free, total), ("disk_drop", lost, days)."""
        now = now or utcnow()
        rep = clean_report(raw)
        self.store._x("delete from disk_progress where device_id=?", (device_id,))  # the scan is done
        self.store._x("insert into disk_reports (device_id, at, report) values (?,?,?) on conflict(device_id) do update set "
                      "at=excluded.at, report=excluded.report", (device_id, now.isoformat(), json.dumps(rep)))
        if not rep["drives"]:
            return []
        drive = rep["drives"][0]
        day = now.date().isoformat()
        self.store._x("insert into disk_history (device_id, day, free, total) values (?,?,?,?) on conflict(device_id, day) do update set "
                      "free=excluded.free, total=excluded.total", (device_id, day, drive["free"], drive["total"]))
        self.store._x("delete from disk_history where device_id=? and day < ?", (device_id, (now - timedelta(days=60)).date().isoformat()))
        alerts: list[tuple] = []
        since = (now - timedelta(days=DROP_DAYS)).date().isoformat()
        rows = self.store._q("select day, free from disk_history where device_id=? and day>=? and day<? order by day limit 1",
                             (device_id, since, day))
        if rows and rows[0]["free"] - drive["free"] > DROP_BYTES:
            days = (now.date() - datetime.fromisoformat(rows[0]["day"]).date()).days
            alerts.append(("disk_drop", rows[0]["free"] - drive["free"], days))
        if drive["total"] and drive["free"] / drive["total"] < LOW_SHARE:
            alerts.append(("disk_low", drive["free"], drive["total"]))
        return alerts

    def set_progress(self, device_id: str, request: str, pct: int) -> None:
        self.store._x("insert into disk_progress (device_id, request, pct, at) values (?,?,?,?) on conflict(device_id) do update set "
                      "request=excluded.request, pct=excluded.pct, at=excluded.at",
                      (device_id, str(request)[:40], max(0, min(100, int(pct))), utcnow().isoformat()))

    def progress(self, device_id: str) -> dict[str, Any] | None:
        rows = self.store._q("select request, pct, at from disk_progress where device_id=?", (device_id,))
        return dict(rows[0]) if rows else None

    def latest(self, device_id: str) -> dict[str, Any] | None:
        rows = self.store._q("select report from disk_reports where device_id=?", (device_id,))
        return json.loads(rows[0]["report"]) if rows else None

    def summaries(self) -> dict[str, dict[str, int]]:
        out = {}
        for r in self.store._q("select device_id, report from disk_reports"):
            rep = json.loads(r["report"])
            if rep.get("drives"):
                out[r["device_id"]] = {"free": rep["drives"][0]["free"], "total": rep["drives"][0]["total"], "at": rep.get("at", 0)}
        return out

    def history(self, device_id: str, days: int = 30) -> list[dict[str, Any]]:
        since = (utcnow() - timedelta(days=days)).date().isoformat()
        return [dict(r) for r in self.store._q("select day, free, total from disk_history where device_id=? and day>=? order by day",
                                               (device_id, since))]


def utc(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)
