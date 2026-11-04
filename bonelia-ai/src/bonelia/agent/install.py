"""Install / uninstall the agent on a Windows PC (one time, as administrator, with the business's consent)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..security import dpapi
from ..security.crypto import DeviceCredentials

TASK_NAME = "BONELIA AI Agent"


def agent_dir() -> Path:
    return Path(os.environ.get("BONELIA_AGENT_DIR") or Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "BONELIA-AI")


def cred_path() -> Path:
    return agent_dir() / "agent.cred"


def state_path() -> Path:
    return agent_dir() / "state.json"


def save_credentials(creds: DeviceCredentials) -> Path:
    d = agent_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = cred_path()
    p.write_bytes(dpapi.protect(creds.to_json()))
    # Only SYSTEM and Administrators may read the agent's key
    subprocess.run(["icacls", str(p), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"],
                   capture_output=True, check=False)
    return p


def load_credentials() -> DeviceCredentials:
    return DeviceCredentials.from_json(dpapi.unprotect(cred_path().read_bytes()))


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    try:
        # errors="replace": schtasks/icacls output on a non-UTF-8 code page (e.g. German cp1252) must
        # never raise a UnicodeDecodeError while being read.
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:  # schtasks/icacls missing (not Windows)
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def _same_file(a: Path, b: Path) -> bool:
    import hashlib

    if not b.is_file() or a.stat().st_size != b.stat().st_size:
        return False
    h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    return h(a) == h(b)


def _copy_program(src: Path, dst: Path) -> None:
    """Copy the agent program; if an older agent is running (re-install / update), stop it first."""
    import time

    if _same_file(src, dst):
        return  # already installed in this version
    for attempt in range(5):
        try:
            shutil.copy2(src, dst)
            return
        except PermissionError:
            if attempt == 0:
                _run(["schtasks", "/End", "/TN", TASK_NAME])
                _run(["taskkill", "/IM", "BoneliaAI-Agent.exe", "/F"])
            time.sleep(1.5)
    shutil.copy2(src, dst)


def install_task(start_now: bool = True) -> tuple[bool, str]:
    """Copy the program to %ProgramData%\\BONELIA-AI and register a SYSTEM task that starts at boot."""
    d = agent_dir()
    d.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False):
        exe = d / "BoneliaAI-Agent.exe"
        try:
            _copy_program(Path(sys.executable), exe)  # keeps running after the USB stick is removed
        except OSError as exc:
            return False, f"copy failed: {exc}"
        command = f'"{exe}" agent'
    else:
        command = f'"{sys.executable}" -m bonelia agent'
    p = _run(["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST",
              "/TR", command])
    if p.returncode != 0:
        return False, (p.stderr or p.stdout).strip()
    # Hide the task in Task Scheduler so it is not visible to staff on the PC (best effort).
    _run(["powershell", "-NoProfile", "-Command",
          "try{$t=Get-ScheduledTask -TaskName '" + TASK_NAME + "' -ErrorAction Stop;"
          "$t.Settings.Hidden=$true; Set-ScheduledTask -InputObject $t | Out-Null}catch{}"])
    if start_now:
        _run(["schtasks", "/Run", "/TN", TASK_NAME])
    return True, command


UPDATE_TASK = "BONELIA AI Agent Update"


def schedule_swap(new_exe: Path) -> tuple[bool, str]:
    """Replace the running agent from OUTSIDE its own task (a one-shot SYSTEM task), then restart it."""
    d = agent_dir()
    exe = d / "BoneliaAI-Agent.exe"
    script = d / "update.ps1"
    script.write_text("\r\n".join([
        "Start-Sleep -Seconds 3",
        f'schtasks /End /TN "{TASK_NAME}" | Out-Null',
        "Start-Sleep -Seconds 3",
        "Get-Process BoneliaAI-Agent -ErrorAction SilentlyContinue | Stop-Process -Force",
        "Start-Sleep -Seconds 1",
        f'Move-Item -Force -LiteralPath "{new_exe}" -Destination "{exe}"',
        f'schtasks /Run /TN "{TASK_NAME}" | Out-Null',
        f'schtasks /Delete /F /TN "{UPDATE_TASK}" | Out-Null',
    ]), encoding="utf-8")
    cmd = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script}"'
    p = _run(["schtasks", "/Create", "/F", "/TN", UPDATE_TASK, "/SC", "ONCE", "/ST", "00:00", "/SD", "01/01/2099",
              "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", cmd])
    if p.returncode != 0:
        return False, (p.stderr or p.stdout).strip()
    r = _run(["schtasks", "/Run", "/TN", UPDATE_TASK])
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def task_installed() -> bool:
    return _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0


def uninstall() -> list[str]:
    done = []
    _run(["schtasks", "/End", "/TN", TASK_NAME])
    if _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME]).returncode == 0:
        done.append("task_removed")
    d = agent_dir()
    for name in ("agent.cred", "state.json", "state.tmp", "agent.log", "BoneliaAI-Agent.exe"):
        try:
            (d / name).unlink()
            done.append(f"{name}_removed")
        except FileNotFoundError:
            pass
        except OSError:
            done.append(f"{name}_in_use")
    try:
        d.rmdir()
    except OSError:
        pass
    return done
