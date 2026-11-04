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
        return subprocess.run(cmd, capture_output=True, text=True, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:  # schtasks/icacls missing (not Windows)
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def install_task(start_now: bool = True) -> tuple[bool, str]:
    """Copy the program to %ProgramData%\\BONELIA-AI and register a SYSTEM task that starts at boot."""
    d = agent_dir()
    d.mkdir(parents=True, exist_ok=True)
    if getattr(sys, "frozen", False):
        exe = d / "BoneliaAI-Agent.exe"
        shutil.copy2(sys.executable, exe)  # keeps running after the USB stick is removed
        command = f'"{exe}" agent'
    else:
        command = f'"{sys.executable}" -m bonelia agent'
    p = _run(["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST",
              "/TR", command])
    if p.returncode != 0:
        return False, (p.stderr or p.stdout).strip()
    if start_now:
        _run(["schtasks", "/Run", "/TN", TASK_NAME])
    return True, command


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
