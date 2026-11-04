"""Guided Windows recovery operations — only Microsoft's own built-in repair tools.

Trust model (different from repairs): recovery runs on a possibly offline/broken PC,
so there is no home-server authorization. The technician is physically present with
the USB and must run it as administrator. Safeguards instead:
* only a fixed set of well-known Windows repair commands (no free-form command line);
* drive letters validated against a strict pattern;
* destructive actions (system restore, chkdsk) require an explicit confirm flag and
  never touch user data files;
* read-only inspections (restore points, disk/SMART, system health) need no confirm.
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

DRIVE = re.compile(r"^[A-Za-z]:$")
_NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class OpResult:
    ok: bool
    output: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _run(cmd: list[str], timeout: int) -> OpResult:
    if sys.platform != "win32":
        return OpResult(False, error="not_windows")
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=_NOWIN)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return OpResult(False, error=type(exc).__name__)
    out = (p.stdout or b"").decode("utf-8", errors="replace")
    err = (p.stderr or b"").decode("utf-8", errors="replace")
    return OpResult(p.returncode == 0, output=(out + err)[-6000:], data={"exit_code": p.returncode})


def _ps(script: str, timeout: int) -> OpResult:
    return _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


# ---------------------------------------------------------------- read-only inspection

def list_restore_points() -> OpResult:
    r = _ps("Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,"
            "@{n='CreationTime';e={$_.ConvertToDateTime($_.CreationTime)}} | ConvertTo-Json -Compress", 60)
    if not r.ok:
        return r
    import json

    try:
        raw = json.loads(r.output or "[]")
    except json.JSONDecodeError:
        raw = []
    items = raw if isinstance(raw, list) else [raw]
    r.data["restore_points"] = [{"sequence": i.get("SequenceNumber"), "description": str(i.get("Description", ""))[:120],
                                 "created": str(i.get("CreationTime", ""))[:19]} for i in items]
    return r


def disk_health() -> OpResult:
    return _ps("Get-PhysicalDisk | Select-Object DeviceId,FriendlyName,MediaType,HealthStatus,"
               "@{n='SizeGB';e={[math]::Round($_.Size/1GB,0)}} | ConvertTo-Json -Compress", 60)


def pending_reboot() -> OpResult:
    return _ps("Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'", 20)


# ---------------------------------------------------------------- repair (admin)

def sfc_scannow() -> OpResult:
    """Scan and repair protected Windows system files."""
    return _run(["sfc", "/scannow"], 1800)


def dism_restore_health() -> OpResult:
    """Repair the Windows component store (fixes what sfc cannot)."""
    return _run(["dism", "/online", "/cleanup-image", "/restorehealth"], 3600)


def schedule_chkdsk(drive: str, confirm: bool) -> OpResult:
    if not DRIVE.match(drive):
        return OpResult(False, error="invalid_drive")
    if not confirm:
        return OpResult(True, data={"would_run": f"chkdsk {drive} /f /r (on next restart)", "needs_confirm": True})
    # /f fix, /r locate bad sectors; schedules on reboot for the system drive instead of locking it now
    p = subprocess.run(["cmd", "/c", f"echo Y| chkdsk {drive} /f /r"], capture_output=True, timeout=120,
                       creationflags=_NOWIN) if sys.platform == "win32" else None
    if p is None:
        return OpResult(False, error="not_windows")
    out = (p.stdout or b"").decode("utf-8", errors="replace") + (p.stderr or b"").decode("utf-8", errors="replace")
    scheduled = "will be checked" in out.lower() or "beim nächsten" in out.lower() or "überprüft" in out.lower()
    return OpResult(p.returncode == 0 or scheduled, output=out[-4000:], data={"scheduled": scheduled})


def restore_to_point(sequence: int, confirm: bool) -> OpResult:
    """Roll Windows back to a restore point. User files are not affected by System Restore."""
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        return OpResult(False, error="invalid_sequence")
    if not confirm:
        return OpResult(True, data={"would_run": f"Restore-Computer -RestorePoint {sequence} (restarts Windows)",
                                    "needs_confirm": True})
    return _ps(f"Restore-Computer -RestorePoint {int(sequence)} -Confirm:$false", 120)


# Guidance only: these need the Windows Recovery Environment (WinRE), not a running Windows.
BOOTREC_GUIDE = {
    "tr": ["Windows açılmıyorsa kurtarma ortamından (WinRE) komut istemini açın ve sırayla deneyin:",
           "bootrec /scanos", "bootrec /fixmbr", "bootrec /fixboot", "bootrec /rebuildbcd",
           "Ardından: sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows", "Gerekirse: startup repair (Başlangıç Onarma)"],
    "de": ["Startet Windows nicht, in der Wiederherstellungsumgebung (WinRE) die Eingabeaufforderung öffnen:",
           "bootrec /scanos", "bootrec /fixmbr", "bootrec /fixboot", "bootrec /rebuildbcd",
           "Danach: sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows", "Falls nötig: Starthilfe"],
    "en": ["If Windows does not boot, open the command prompt in the Recovery Environment (WinRE) and try:",
           "bootrec /scanos", "bootrec /fixmbr", "bootrec /fixboot", "bootrec /rebuildbcd",
           "Then: sfc /scannow /offbootdir=C:\\ /offwindir=C:\\Windows", "If needed: Startup Repair"],
}


OPERATIONS = {
    "restore_points": {"fn": lambda p: list_restore_points(), "confirm": False, "readonly": True},
    "disk_health": {"fn": lambda p: disk_health(), "confirm": False, "readonly": True},
    "pending_reboot": {"fn": lambda p: pending_reboot(), "confirm": False, "readonly": True},
    "sfc": {"fn": lambda p: sfc_scannow(), "confirm": False, "readonly": False},
    "dism": {"fn": lambda p: dism_restore_health(), "confirm": False, "readonly": False},
    "chkdsk": {"fn": lambda p: schedule_chkdsk(p.get("drive", ""), bool(p.get("confirm"))), "confirm": True, "readonly": False},
    "restore": {"fn": lambda p: restore_to_point(p.get("sequence"), bool(p.get("confirm"))), "confirm": True, "readonly": False},
}
