"""Bounded, encrypted offline queue for events captured while the server is unreachable.

Only analysis REQUESTS are queued — never interventions (no remote action without
a live, authenticated connection).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ..contracts import DiagnosticEvent
from ..security.crypto import DataKey

MAX_ENTRIES = 200
MAX_BYTES = 5 * 1024 * 1024


class OfflineQueue:
    def __init__(self, directory: Path, key: DataKey):
        self.dir = directory
        self.key = key
        self.dir.mkdir(parents=True, exist_ok=True)

    def _files(self) -> list[Path]:
        return sorted(self.dir.glob("*.bnq"))

    def size(self) -> int:
        return len(self._files())

    def push(self, events: list[DiagnosticEvent]) -> int:
        """Store events; drops the OLDEST entries when limits are exceeded. Returns dropped count."""
        blob = self.key.encrypt(json.dumps([e.model_dump(mode="json") for e in events[:25]]).encode(), aad=b"bonelia-queue")
        # time prefix keeps FIFO order; random suffix prevents same-tick collisions (data loss) on Windows
        name = f"{time.time_ns():020d}-{os.urandom(6).hex()}.bnq"
        (self.dir / name).write_bytes(blob)
        dropped = 0
        files = self._files()
        total = sum(f.stat().st_size for f in files)
        while files and (len(files) > MAX_ENTRIES or total > MAX_BYTES):
            f = files.pop(0)
            total -= f.stat().st_size
            f.unlink(missing_ok=True)
            dropped += 1
        return dropped

    def drain(self, send, max_entries: int | None = None) -> tuple[int, int]:
        """Call `send(events)` for each entry; delete on success. Stops at first failure."""
        sent = failed = 0
        for f in self._files()[:max_entries]:
            try:
                events = [DiagnosticEvent.model_validate(x) for x in json.loads(self.key.decrypt(f.read_bytes(), aad=b"bonelia-queue"))]
            except (ValueError, OSError):
                f.unlink(missing_ok=True)  # corrupted entry: discard safely
                failed += 1
                continue
            try:
                send(events)
            except Exception:
                failed += 1
                break
            f.unlink(missing_ok=True)
            sent += 1
        return sent, failed
