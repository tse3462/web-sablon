from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

FIX = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def fixture_json(name: str) -> dict:
    return json.loads(fixture_text(name))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread:
    """Runs a real uvicorn server on 127.0.0.1 in a background thread."""

    def __init__(self, app, port: int | None = None):
        self.port = port or free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started:
            if time.time() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture
def server_thread():
    return ServerThread


def write_test_event(source: str, event_id: int, message: str) -> None:
    """Write a controlled ERROR event to the Windows Application log (eventcreate, with a PowerShell fallback).

    eventcreate occasionally fails on CI runners without a useful message; the fallback keeps tests deterministic.
    """
    import subprocess
    import time

    last = ""
    for _ in range(3):
        p = subprocess.run(["eventcreate", "/T", "ERROR", "/ID", str(event_id), "/L", "APPLICATION", "/SO", source, "/D", message],
                           capture_output=True, text=True)
        if p.returncode == 0:
            return
        last = (p.stdout + p.stderr).strip()
        time.sleep(1)
    msg = message.replace("'", "''")
    ps = (f"if (-not [System.Diagnostics.EventLog]::SourceExists('{source}')) {{ New-EventLog -LogName Application -Source '{source}' }}; "
          f"Write-EventLog -LogName Application -Source '{source}' -EventId {event_id} -EntryType Error -Message '{msg}'")
    p = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"could not write test event: eventcreate={last!r} powershell={p.stderr.strip()!r}")
