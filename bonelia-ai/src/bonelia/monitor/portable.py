"""Portable (USB) runtime layout and lifecycle.

BONELIA-AI-Portable/
  BoneliaAI.exe
  config/     device.vault (encrypted), settings.json, salt
  adapters/   adapter manifests shipped with the build
  resources/
  reports/    encrypted reports (*.bnr)
  manifests/  build manifest with file hashes
  queue/      encrypted offline event queue (bounded)

No autorun is used: the operator starts the program deliberately.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Callable

SUBDIRS = ("config", "adapters", "resources", "reports", "manifests", "queue")


def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    env = os.environ.get("BONELIA_HOME")
    return Path(env).resolve() if env else Path.cwd().resolve()


class PortableHome:
    def __init__(self, root: Path | None = None):
        self.root = (root or base_dir()).resolve()

    def ensure(self) -> "PortableHome":
        for d in SUBDIRS:
            (self.root / d).mkdir(parents=True, exist_ok=True)
        return self

    def path(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)

    @property
    def vault_path(self) -> Path:
        return self.path("config", "device.vault")

    def salt(self) -> str:
        """Per-USB random salt used to pseudonymise host names. Not a secret key."""
        p = self.path("config", "salt")
        if not p.is_file():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(secrets.token_hex(16), encoding="utf-8")
        return p.read_text(encoding="utf-8").strip()

    def settings(self) -> dict:
        p = self.path("config", "settings.json")
        if not p.is_file():
            return {"language": "tr", "allow_cloud_default": False, "log_paths": []}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return {"language": "tr", "allow_cloud_default": False, "log_paths": []}

    def save_settings(self, data: dict) -> None:
        self.path("config").mkdir(parents=True, exist_ok=True)
        self.path("config", "settings.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def watch_removal(root: Path, on_removed: Callable[[], None], interval_s: float = 2.0) -> threading.Thread:
    """When the USB stick disappears, portable operation ends (Master prompt §35 step 13)."""

    def loop() -> None:
        while True:
            time.sleep(interval_s)
            try:
                present = root.exists() and any(True for _ in root.iterdir())
            except OSError:
                present = False
            if not present:
                on_removed()
                return

    t = threading.Thread(target=loop, name="bonelia-usb-watch", daemon=True)
    t.start()
    return t
