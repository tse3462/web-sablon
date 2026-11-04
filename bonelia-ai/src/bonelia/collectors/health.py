"""Disk health and backup freshness (read-only, Windows).

Nothing here changes the system. It reads:
* Windows' own storage health data (Get-PhysicalDisk health status, storage
  reliability counters: wear, temperature, uncorrected read/write errors) and the
  SMART failure prediction flag (MSStorageDriver_FailurePredictStatus);
* the Windows Backup event log (last successful backup);
* file timestamps (never contents) in backup folders the owner configured.

These checks are slower than the 5-minute agent cycle needs, so results are cached
(disk health 6 h, backups 1 h; a changed backup policy is re-checked immediately).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .windows_events import _parse_time, decode_tool_output

TIMEOUT_S = 60
DISK_TTL_S = 6 * 3600
BACKUP_TTL_S = 3600
MAX_FOLDER_ENTRIES = 20_000
MAX_FOLDER_DEPTH = 4

_CACHE: dict[str, tuple[float, Any]] = {}


def _cached(key: str, ttl_s: float, fn: Callable[[], Any]) -> Any:
    now = time.monotonic()
    hit = _CACHE.get(key)
    if hit is not None and now - hit[0] < ttl_s:
        return hit[1]
    value = fn()
    _CACHE[key] = (now, value)
    return value


def _run(cmd: list[str], timeout: int = TIMEOUT_S) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, decode_tool_output(p.stdout)


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ------------------------------------------------------------------ disk health

_DISK_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$disks = @()
foreach ($d in @(Get-PhysicalDisk)) {
  $r = $null
  try { $r = $d | Get-StorageReliabilityCounter } catch {}
  $disks += [pscustomobject]@{
    name = [string]$d.FriendlyName; media = [string]$d.MediaType; bus = [string]$d.BusType
    health = [string]$d.HealthStatus; operational = [string]($d.OperationalStatus -join ',')
    size_gb = [math]::Round($d.Size / 1GB, 0)
    wear = $r.Wear; temperature = $r.Temperature
    read_errors = $r.ReadErrorsUncorrected; write_errors = $r.WriteErrorsUncorrected
  }
}
$pf = @()
try { $pf = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus | Where-Object { $_.PredictFailure } | ForEach-Object { [string]$_.InstanceName }) } catch {}
ConvertTo-Json -Depth 4 -Compress -InputObject ([pscustomobject]@{ disks = $disks; predict_failure = $pf })
"""


def disk_health() -> tuple[dict[str, Any], str]:
    empty: dict[str, Any] = {"disks": [], "predict_failure": []}
    if sys.platform != "win32":
        return empty, "unavailable:not_windows"
    try:
        rc, out = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _DISK_PS])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return empty, f"error:{type(exc).__name__}"
    try:
        data = json.loads(out.strip() or "{}")
    except ValueError:
        return empty, f"error:unparsable(rc={rc})"
    disks = [d for d in _as_list(data.get("disks")) if isinstance(d, dict)]
    return {"disks": disks, "predict_failure": [str(x)[:200] for x in _as_list(data.get("predict_failure"))]}, f"ok:{len(disks)}"


def cached_disk_health() -> tuple[dict[str, Any], str]:
    return _cached("disk", DISK_TTL_S, disk_health)


# ------------------------------------------------------------------ backups

def _wevtutil_newest(query: str | None) -> tuple[datetime | None, str]:
    cmd = ["wevtutil", "qe", "Microsoft-Windows-Backup", "/c:1", "/rd:true", "/f:xml"]
    if query:
        cmd.insert(3, f"/q:{query}")
    try:
        rc, out = _run(cmd, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"error:{type(exc).__name__}"
    if rc != 0:
        return None, "not_found"
    m = re.search(r"SystemTime=[\"']([^\"']+)[\"']", out)
    return (_parse_time(m.group(1)) if m else None), "ok"


def windows_backup() -> dict[str, Any]:
    """Last successful Windows Backup (event 4) and the newest backup event of any kind."""
    if sys.platform != "win32":
        return {"status": "unavailable:not_windows", "last_success": None, "last_event": None}
    success, st = _wevtutil_newest("*[System[(EventID=4)]]")
    if st != "ok":
        return {"status": st, "last_success": None, "last_event": None}
    last, _ = _wevtutil_newest(None)
    return {"status": "ok", "last_success": success.isoformat() if success else None,
            "last_event": last.isoformat() if last else None}


def folder_state(path: str, max_entries: int = MAX_FOLDER_ENTRIES, max_depth: int = MAX_FOLDER_DEPTH) -> dict[str, Any]:
    """Newest file time below a backup folder. Reads timestamps only, never file contents.

    The creation time counts too: a copy-based backup keeps the original modification
    time, but the copy itself is created when the backup runs."""
    p = Path(path)
    out: dict[str, Any] = {"path": path, "exists": False, "files": 0, "newest": None}
    try:
        if not p.exists():
            return out
    except OSError:
        return out
    out["exists"] = True
    newest = 0.0

    def consider(f: Path) -> None:
        nonlocal newest
        try:
            st = f.stat()
        except OSError:
            return
        out["files"] += 1
        newest = max(newest, st.st_mtime, float(getattr(st, "st_birthtime", 0) or 0))

    if p.is_file():
        consider(p)
    else:
        base = len(p.parts)
        seen = 0
        for dirpath, dirnames, filenames in os.walk(p, followlinks=False):
            if len(Path(dirpath).parts) - base >= max_depth:
                dirnames[:] = []
            for name in filenames:
                seen += 1
                if seen > max_entries:
                    break
                consider(Path(dirpath) / name)
            if seen > max_entries:
                break
    if newest:
        out["newest"] = datetime.fromtimestamp(newest, tz=timezone.utc).isoformat()
    return out


def backup_state(policy: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    if sys.platform != "win32":
        return {"folders": [], "windows": {"status": "unavailable:not_windows"}}, "unavailable:not_windows"
    paths = [str(x) for x in (policy or {}).get("paths", [])][:5]
    state = {"folders": [folder_state(x) for x in paths], "windows": windows_backup()}
    return state, f"ok:folders={len(paths)},windows={state['windows']['status']}"


def cached_backup_state(policy: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    key = "backup|" + json.dumps(policy or {}, sort_keys=True)  # a new policy is checked at once
    return _cached(key, BACKUP_TTL_S, lambda: backup_state(policy))
