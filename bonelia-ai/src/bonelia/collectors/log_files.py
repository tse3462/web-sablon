"""Bounded reader for application log files the operator explicitly authorised.

Large files are read from the end with a hard byte cap, so a multi-GB log never
loads into memory. Only lines that look like errors are kept.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

MAX_TAIL_BYTES = 2 * 1024 * 1024
MAX_LINES = 200
ERROR_LINE = re.compile(r"(?i)\b(fatal|critical|error|exception|fehler|hata|failed|timeout|refused|traceback|unhandled)\b")
ALLOWED_SUFFIXES = {".log", ".txt", ".out", ".err", ".json", ".jsonl"}


def tail_error_lines(path: Path, max_bytes: int = MAX_TAIL_BYTES, max_lines: int = MAX_LINES) -> tuple[list[str], str]:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return [], "error:not_found"
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        return [], "denied:suffix"
    if not resolved.is_file():
        return [], "error:not_a_file"
    try:
        size = resolved.stat().st_size
        with open(resolved, "rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes, os.SEEK_SET)
            raw = fh.read(max_bytes)
    except OSError as exc:
        return [], f"error:{type(exc).__name__}"
    text = raw.decode("utf-8", errors="replace")
    if size > max_bytes:
        text = text.split("\n", 1)[-1]  # drop the partial first line
    lines = [ln.strip()[:1000] for ln in text.splitlines() if ERROR_LINE.search(ln)]
    return lines[-max_lines:], f"ok:{len(lines[-max_lines:])}"
