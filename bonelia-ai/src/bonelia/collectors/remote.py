"""RustDesk remote access (user request 06.11.2026): the agent reports this PC's RustDesk ID so the
control panel can open a remote session with one tap.

Only the ID and whether RustDesk is installed and running are read. The RustDesk password is never
read or sent: RustDesk asks for it when the session opens.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

_ID_LINE = re.compile(r"""^\s*id\s*=\s*['"]([0-9 ]{8,16})['"]""", re.MULTILINE)
_DIGITS = re.compile(r"(\d[\d ]{6,14}\d)")


def parse_rustdesk_id(text: str) -> str | None:
    """The RustDesk ID (8-12 digits) from `rustdesk --get-id` output or a RustDesk.toml; None if absent."""
    if not text:
        return None
    m = _ID_LINE.search(text) or _DIGITS.search(text)
    if not m:
        return None
    digits = m.group(1).replace(" ", "")
    return digits if 8 <= len(digits) <= 12 else None


def _default_exe_paths() -> list[Path]:
    roots = [os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
    return [Path(r) / "RustDesk" / "rustdesk.exe" for r in roots]


def _default_config_paths() -> list[Path]:
    # Installed as a service, RustDesk keeps its ID in the LocalService profile; otherwise in the user's profile.
    paths = [Path(os.environ.get("SystemRoot", r"C:\Windows")) / "ServiceProfiles" / "LocalService" / "AppData" / "Roaming"
             / "RustDesk" / "config" / "RustDesk.toml"]
    if os.environ.get("APPDATA"):
        paths.append(Path(os.environ["APPDATA"]) / "RustDesk" / "config" / "RustDesk.toml")
    return paths


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def rustdesk_info(exe_paths: list[Path] | None = None, config_paths: list[Path] | None = None,
                  run: Callable[[list[str]], tuple[int, str]] = _run, windows: bool | None = None) -> dict | None:
    """{installed, rustdesk_id, service}; None on systems other than Windows."""
    if not (sys.platform == "win32" if windows is None else windows):
        return None
    exe = next((p for p in (exe_paths if exe_paths is not None else _default_exe_paths()) if p.is_file()), None)
    if exe is None:
        return {"installed": False, "rustdesk_id": None, "service": "missing"}
    code, out = run([str(exe), "--get-id"])
    rid = parse_rustdesk_id(out) if code == 0 else None
    if rid is None:
        for cfg in config_paths if config_paths is not None else _default_config_paths():
            try:
                rid = parse_rustdesk_id(cfg.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if rid:
                break
    _, sc = run(["sc", "query", "RustDesk"])
    service = "running" if "RUNNING" in sc else "stopped" if "STOPPED" in sc else "missing"
    return {"installed": True, "rustdesk_id": rid, "service": service}
