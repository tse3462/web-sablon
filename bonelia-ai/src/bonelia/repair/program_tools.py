"""Client-side executors of the rescue tools (user request 06.11.2026).

* ``windows.restart_hung_app``: a program whose window has not answered for minutes is ended and started
  again with its own command line, in the signed-in user's session.
* ``windows.close_program``: a program is asked to close like a click on its X (never forced -- a program
  with unsaved work asks to save and stays open), and optionally started again.

Safety: the process number must still belong to that program and to the signed-in user's session; Windows'
own programs, remote access and BONELIA are refused (same list as the rescue logic); every action is
checked afterwards. The PC itself is reached through ``ops`` (Windows implementation in
collectors.programs; tests use a fake).
"""

from __future__ import annotations

from typing import Any

from ..agent.rescue import is_protected
from .tools import ExecResult

END_WAIT_S = 10
CLOSE_WAIT_S = 20
START_WAIT_S = 4


def _ops(ops):
    if ops is not None:
        return ops
    from ..collectors.programs import windows_ops
    return windows_ops()


def _check(params: dict[str, Any], ops) -> tuple[dict | None, ExecResult | None]:
    name = str(params.get("name") or "")
    if is_protected(name):
        return None, ExecResult(False, {"error": "protected"})
    info = ops.info(int(params["pid"]))
    if info is None:
        return None, ExecResult(False, {"error": "not_running"})
    if str(info.get("name") or "").lower() != name.lower():
        return None, ExecResult(False, {"error": "pid_changed"})
    if not info.get("own_session"):
        return None, ExecResult(False, {"error": "other_session"})
    return info, None


def _start(ops, info: dict) -> int | None:
    try:
        return ops.launch(list(info.get("cmd") or []), info.get("cwd"))
    except Exception:
        return None


def restart_hung_app(params: dict[str, Any], dry_run: bool, ops=None) -> ExecResult:
    ops = _ops(ops)
    info, refused = _check(params, ops)
    if refused:
        return refused
    if dry_run:
        return ExecResult(True, {"note": "dry_run"})
    pid = int(params["pid"])
    if ops.is_hung(pid) is False:  # it answers again: nothing to do
        return ExecResult(True, {"before": "hung", "after": "recovered"})
    ops.kill(pid)
    for _ in range(END_WAIT_S * 2):
        if not ops.alive(pid):
            break
        ops.sleep(0.5)
    if ops.alive(pid):
        return ExecResult(False, {"before": "hung", "error": "kill_failed"})
    new = _start(ops, info)
    return ExecResult(True, {"before": "hung", "after": "restarted" if new else "closed", "new_pid": new,
                             "note": None if new else "start_failed"})


def verify_restarted(params: dict[str, Any], result: ExecResult, ops=None) -> bool:
    ops = _ops(ops)
    if result.detail.get("after") == "recovered":
        return ops.alive(int(params["pid"])) and ops.is_hung(int(params["pid"])) is not True
    new = result.detail.get("new_pid")
    if not new:
        return False
    ops.sleep(START_WAIT_S)  # give the program a moment; a program that dies right away failed
    return bool(ops.alive(int(new)))


def close_program(params: dict[str, Any], dry_run: bool, ops=None) -> ExecResult:
    ops = _ops(ops)
    info, refused = _check(params, ops)
    if refused:
        return refused
    if dry_run:
        return ExecResult(True, {"note": "dry_run"})
    pid = int(params["pid"])
    if not ops.close(pid, CLOSE_WAIT_S):
        return ExecResult(False, {"before": "open", "after": "still_open", "note": "asks_to_save_or_refused"})
    if params.get("restart") is True:
        new = _start(ops, info)
        return ExecResult(True, {"before": "open", "after": "reopened" if new else "closed", "new_pid": new,
                                 "note": None if new else "start_failed"})
    return ExecResult(True, {"before": "open", "after": "closed"})


def verify_closed(params: dict[str, Any], result: ExecResult, ops=None) -> bool:
    ops = _ops(ops)
    if ops.alive(int(params["pid"])):
        return False
    if params.get("restart") is True:
        new = result.detail.get("new_pid")
        if not new:
            return False
        ops.sleep(START_WAIT_S)
        return bool(ops.alive(int(new)))
    return True


EXECUTORS = {
    "windows.restart_hung_app": (lambda p, d: restart_hung_app(p, d), lambda p, r: verify_restarted(p, r)),
    "windows.close_program": (lambda p, d: close_program(p, d), lambda p, r: verify_closed(p, r)),
}
