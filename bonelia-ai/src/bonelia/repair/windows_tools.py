"""Client-side Windows repair executors (run by the USB monitor on the customer PC).

Safety properties:
* Only allow-listed actions with a validated service name that exists on this PC
  (no free-form command line is ever built from AI output or event text).
* Critical Windows services are refused.
* Elevation goes through Windows' own UAC prompt; BONELİA AI never bypasses it.
* Success is decided by an independent check of the service state afterwards.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from typing import Any, Callable

from .tools import ExecResult

SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")

# Services whose (re)start can lock up the machine or weaken its security: never touched.
CRITICAL_SERVICES = {s.lower() for s in (
    "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "lsass", "SamSs", "EventLog", "Winmgmt", "WinDefend",
    "SecurityHealthService", "Sense", "mpssvc", "BFE", "CryptSvc", "Power", "ProfSvc", "Schedule", "gpsvc",
    "TrustedInstaller", "BrokerInfrastructure", "CoreMessagingRegistrar", "SystemEventsBroker", "Dhcp", "Dnscache",
    "nsi", "PlugPlay", "UserManager", "TermService", "KeyIso", "VaultSvc", "Netlogon", "W32Time",
)}

# Automatic services that Windows itself routinely leaves stopped (trigger/delayed start): not a fault.
NORMALLY_STOPPED = {s.lower() for s in (
    "sppsvc", "gupdate", "gupdatem", "edgeupdate", "edgeupdatem", "MapsBroker", "RemoteRegistry", "BITS", "DoSvc",
    "UsoSvc", "wuauserv", "WbioSrvc", "tiledatamodelsvc", "ShellHWDetection", "CDPSvc", "sedsvc", "WaaSMedicSvc",
    "uhssvc", "GoogleUpdaterService", "GoogleUpdaterInternalService", "MicrosoftEdgeElevationService",
    "OneSyncSvc", "TrkWks", "NetTcpPortSharing", "AdobeARMservice", "ClickToRunSvc", "IntelAudioService",
    "InstallService", "AppXSvc", "ClipSVC", "StorSvc", "LicenseManager", "TokenBroker", "wscsvc",
)}


def service_info(name: str) -> dict[str, Any] | None:
    if sys.platform != "win32":
        return None
    import psutil

    try:
        return psutil.win_service_get(name).as_dict()  # type: ignore[attr-defined]
    except Exception:
        return None


def _check_name(name: Any) -> str | None:
    if not isinstance(name, str) or not SERVICE_NAME.match(name):
        return "invalid_service_name"
    if name.lower() in CRITICAL_SERVICES:
        return "critical_service_refused"
    return None


def _elevated(ps_command: str, timeout_s: int) -> tuple[int, str]:
    """Run one PowerShell command elevated (Windows shows its own UAC prompt if needed)."""
    outer = ("$p = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
             f"-ArgumentList '-NoProfile','-NonInteractive','-Command','{ps_command}'; exit $p.ExitCode")
    try:
        p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", outer], capture_output=True,
                           timeout=timeout_s, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, type(exc).__name__
    err = (p.stderr or b"").decode("utf-8", errors="replace")[-300:]
    if "canceled by the user" in err or "abgebrochen" in err or "iptal" in err:
        return 1223, "uac_declined"
    return p.returncode, err


def _wait_running(name: str, timeout_s: float = 20.0, sleep: Callable[[float], None] = time.sleep) -> str | None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        info = service_info(name)
        status = info.get("status") if info else None
        if status == "running":
            return status
        sleep(1.0)
    return status


def start_service(params: dict[str, Any], dry_run: bool) -> ExecResult:
    name = params.get("service_name")
    if err := _check_name(name):
        return ExecResult(False, {"error": err})
    info = service_info(name)
    if info is None:
        return ExecResult(False, {"error": "service_not_found_or_not_windows"})
    before = {"status": info.get("status"), "start_type": info.get("start_type"), "display_name": info.get("display_name")}
    if dry_run:
        return ExecResult(True, {"would_run": f"Start-Service -Name {name}", "before": before})
    if info.get("status") == "running":
        return ExecResult(True, {"before": before, "note": "already_running"})
    if info.get("start_type") == "disabled":
        return ExecResult(False, {"before": before, "error": "service_disabled_by_configuration"})
    code, err = _elevated(f"Start-Service -Name {name}", 90)
    return ExecResult(code == 0, {"before": before, "exit_code": code, "error": err if code else None})


def restart_service(params: dict[str, Any], dry_run: bool) -> ExecResult:
    name = params.get("service_name")
    if err := _check_name(name):
        return ExecResult(False, {"error": err})
    info = service_info(name)
    if info is None:
        return ExecResult(False, {"error": "service_not_found_or_not_windows"})
    before = {"status": info.get("status"), "start_type": info.get("start_type"), "display_name": info.get("display_name")}
    if dry_run:
        return ExecResult(True, {"would_run": f"Restart-Service -Name {name} -Force", "before": before})
    code, err = _elevated(f"Restart-Service -Name {name} -Force", 120)
    return ExecResult(code == 0, {"before": before, "exit_code": code, "error": err if code else None})


def verify_running(params: dict[str, Any], result: ExecResult) -> bool:
    status = _wait_running(params["service_name"])
    result.detail["after"] = {"status": status}
    return status == "running"


EXECUTORS: dict[str, tuple[Callable[[dict[str, Any], bool], ExecResult], Callable[[dict[str, Any], ExecResult], bool]]] = {
    "windows.start_service": (start_service, verify_running),
    "windows.restart_service": (restart_service, verify_running),
}
