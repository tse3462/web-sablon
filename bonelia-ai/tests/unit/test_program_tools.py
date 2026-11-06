"""Executors of the rescue tools: checked against the PC itself before anything happens (the program number must
still be that program, in the signed-in user's session), never a Windows program, and verified afterwards."""

from bonelia.repair import program_tools as pt


class Ops:
    def __init__(self, **procs):
        self.p = {int(k[1:]): v for k, v in procs.items()}
        self.calls = []
        self.next_pid = 900

    def info(self, pid):
        v = self.p.get(pid)
        if not v or not v.get("alive", True):
            return None
        return {"name": v["name"], "own_session": v.get("own", True), "cmd": v.get("cmd", ["C:\\P\\" + v["name"]]), "cwd": "C:\\P"}

    def is_hung(self, pid):
        return self.p[pid].get("hung", False)

    def kill(self, pid):
        self.calls.append(("kill", pid))
        if not self.p[pid].get("unkillable"):
            self.p[pid]["alive"] = False

    def close(self, pid, timeout_s):
        self.calls.append(("close", pid))
        if self.p[pid].get("asks_to_save"):
            return False
        self.p[pid]["alive"] = False
        return True

    def launch(self, cmd, cwd):
        self.calls.append(("launch", tuple(cmd), cwd))
        self.next_pid += 1
        self.p[self.next_pid] = {"name": cmd[0].rsplit("\\", 1)[-1], "alive": True}
        return self.next_pid

    def alive(self, pid):
        v = self.p.get(pid)
        return bool(v and v.get("alive", True))

    def sleep(self, s):
        pass


def test_hung_program_is_killed_and_started_again_with_its_own_command_line():
    ops = Ops(p10={"name": "Kasse.exe", "hung": True, "cmd": ["C:\\Kasse\\Kasse.exe", "/filiale", "2"]})
    r = pt.restart_hung_app({"pid": 10, "name": "Kasse.exe"}, False, ops=ops)
    assert r.ok and r.detail["before"] == "hung" and r.detail["after"] == "restarted"
    assert ops.calls == [("kill", 10), ("launch", ("C:\\Kasse\\Kasse.exe", "/filiale", "2"), "C:\\P")]
    assert pt.verify_restarted({"pid": 10, "name": "Kasse.exe"}, r, ops=ops)


def test_a_program_that_answers_again_is_left_alone():
    ops = Ops(p10={"name": "Kasse.exe", "hung": False})
    r = pt.restart_hung_app({"pid": 10, "name": "Kasse.exe"}, False, ops=ops)
    assert r.ok and r.detail["after"] == "recovered" and ops.calls == []
    assert pt.verify_restarted({"pid": 10, "name": "Kasse.exe"}, r, ops=ops)


def test_refused_when_the_number_is_now_another_program_or_another_users_or_protected():
    ops = Ops(p10={"name": "EXCEL.EXE", "hung": True}, p11={"name": "Kasse.exe", "hung": True, "own": False},
              p12={"name": "explorer.exe", "hung": True})
    assert pt.restart_hung_app({"pid": 10, "name": "Kasse.exe"}, False, ops=ops).detail["error"] == "pid_changed"
    assert pt.restart_hung_app({"pid": 11, "name": "Kasse.exe"}, False, ops=ops).detail["error"] == "other_session"
    assert pt.restart_hung_app({"pid": 12, "name": "explorer.exe"}, False, ops=ops).detail["error"] == "protected"
    assert pt.restart_hung_app({"pid": 13, "name": "Kasse.exe"}, False, ops=ops).detail["error"] == "not_running"
    assert pt.close_program({"pid": 12, "name": "explorer.exe", "restart": False}, False, ops=ops).detail["error"] == "protected"
    assert ops.calls == []


def test_a_program_that_cannot_be_ended_is_reported_as_failed():
    ops = Ops(p10={"name": "Kasse.exe", "hung": True, "unkillable": True})
    r = pt.restart_hung_app({"pid": 10, "name": "Kasse.exe"}, False, ops=ops)
    assert not r.ok and r.detail["error"] == "kill_failed" and ("launch", ("C:\\P\\Kasse.exe",), "C:\\P") not in ops.calls


def test_dry_run_changes_nothing():
    ops = Ops(p10={"name": "Kasse.exe", "hung": True})
    assert pt.restart_hung_app({"pid": 10, "name": "Kasse.exe"}, True, ops=ops).detail["note"] == "dry_run"
    assert pt.close_program({"pid": 10, "name": "Kasse.exe", "restart": True}, True, ops=ops).detail["note"] == "dry_run"
    assert ops.calls == []


def test_close_is_polite_and_reopens_when_asked():
    ops = Ops(p11={"name": "chrome.exe", "cmd": ["C:\\Chrome\\chrome.exe"]})
    r = pt.close_program({"pid": 11, "name": "chrome.exe", "restart": True}, False, ops=ops)
    assert r.ok and r.detail["after"] == "reopened" and ops.calls[0] == ("close", 11)
    assert ("kill", 11) not in ops.calls  # never forced
    assert pt.verify_closed({"pid": 11, "name": "chrome.exe", "restart": True}, r, ops=ops)
    ops2 = Ops(p11={"name": "chrome.exe"})
    r2 = pt.close_program({"pid": 11, "name": "chrome.exe", "restart": False}, False, ops=ops2)
    assert r2.ok and r2.detail["after"] == "closed" and [c[0] for c in ops2.calls] == ["close"]
    assert pt.verify_closed({"pid": 11, "name": "chrome.exe", "restart": False}, r2, ops=ops2)


def test_a_program_with_unsaved_work_stays_open():
    ops = Ops(p11={"name": "WINWORD.EXE", "asks_to_save": True})
    r = pt.close_program({"pid": 11, "name": "WINWORD.EXE", "restart": True}, False, ops=ops)
    assert not r.ok and r.detail["after"] == "still_open" and [c[0] for c in ops.calls] == ["close"]
    assert ops.alive(11)


def test_tools_are_in_the_agent_executor_table():
    from bonelia.repair.windows_tools import EXECUTORS
    assert "windows.restart_hung_app" in EXECUTORS and "windows.close_program" in EXECUTORS
