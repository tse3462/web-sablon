"""System, process, service and installed-application metadata (read-only)."""

from __future__ import annotations

import platform
import socket
import sys
import time
from dataclasses import dataclass

import psutil

from ..contracts import AppIdentity, SystemSnapshot
from ..security.redact import pseudonymize


def snapshot(salt: str) -> SystemSnapshot:
    disks = []
    for idx, part in enumerate(psutil.disk_partitions(all=False)[:12]):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({
            # Drive letters are not personal; Unix mount paths may contain user names.
            "mount": part.mountpoint if sys.platform == "win32" else ("/" if part.mountpoint == "/" else f"mount{idx}"),
            "fstype": part.fstype,
            "total_gb": round(usage.total / 1024**3, 1),
            "used_percent": usage.percent,
        })
    vm = psutil.virtual_memory()
    return SystemSnapshot(
        hostname_ref=pseudonymize(socket.gethostname(), salt),
        os=platform.system(),
        os_version=platform.version()[:80],
        cpu_count=psutil.cpu_count(logical=True),
        cpu_percent=psutil.cpu_percent(interval=0.3),
        memory_total_mb=int(vm.total / 1024**2),
        memory_used_percent=vm.percent,
        disks=disks,
        uptime_s=int(time.time() - psutil.boot_time()),
        is_windows=sys.platform == "win32",
    )


@dataclass
class ProcInfo:
    name: str
    pid: int
    cpu_percent: float
    memory_mb: float


def top_processes(limit: int = 15) -> list[ProcInfo]:
    """Process names and resource usage only — never command lines (may hold secrets)."""
    procs = list(psutil.process_iter(["name", "pid"]))
    for p in procs:
        try:
            p.cpu_percent(None)
        except (psutil.Error, OSError):
            pass
    time.sleep(0.3)
    out: list[ProcInfo] = []
    for p in procs:
        try:
            out.append(ProcInfo(name=(p.info.get("name") or "?")[:120], pid=p.pid,
                                cpu_percent=p.cpu_percent(None), memory_mb=round(p.memory_info().rss / 1024**2, 1)))
        except (psutil.Error, OSError):
            continue
    out.sort(key=lambda x: (x.cpu_percent, x.memory_mb), reverse=True)
    return out[:limit]


def services() -> tuple[list[dict], str]:
    if sys.platform != "win32":
        return [], "unavailable:not_windows"
    items: list[dict] = []
    try:
        for svc in psutil.win_service_iter():  # type: ignore[attr-defined]
            try:
                info = svc.as_dict(attrs=["name", "display_name", "status", "start_type"])
            except (psutil.Error, OSError):
                continue
            items.append(info)
    except (psutil.Error, OSError) as exc:
        return items, f"error:{type(exc).__name__}"
    return items, f"ok:{len(items)}"


def installed_apps(limit: int = 500) -> tuple[list[AppIdentity], str]:
    """Installed programs from the Windows uninstall registry keys (name/publisher/version only)."""
    if sys.platform != "win32":
        return [], "unavailable:not_windows"
    import winreg  # type: ignore[import-not-found]

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen: dict[str, AppIdentity] = {}
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                except OSError:
                    continue
                with sub:
                    def val(n: str) -> str | None:
                        try:
                            v = winreg.QueryValueEx(sub, n)[0]
                            return str(v)[:200] if v else None
                        except OSError:
                            return None
                    name = val("DisplayName")
                    if not name or val("SystemComponent") == "1":
                        continue
                    app_id = "win:" + name.lower()[:100]
                    seen.setdefault(app_id, AppIdentity(app_id=app_id, name=name, publisher=val("Publisher"),
                                                        version=val("DisplayVersion")))
                if len(seen) >= limit:
                    break
    return sorted(seen.values(), key=lambda a: a.name.lower()), f"ok:{len(seen)}"
