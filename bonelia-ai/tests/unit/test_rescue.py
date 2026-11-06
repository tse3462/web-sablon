"""Automatic rescue of a stuck PC (user request 06.11.2026): a program that hangs for minutes is restarted, and
when the memory stays full the biggest program is closed politely and opened again -- without the owner."""

from bonelia.agent.rescue import HUNG_AFTER_S, MEM_HIGH_FOR_S, Rescue, is_protected


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def proc(pid, name, mb=300, hung=False, started=1.0):
    return {"pid": pid, "name": name, "mb": mb, "hung": hung, "started": started}


def make(snaps, outcome="executed_verified"):
    clock, calls, state = Clock(), [], {}
    box = {"snap": snaps}

    def act(tool, params):
        calls.append((tool, dict(params)))
        return {"tool_id": tool, "outcome": outcome, "reasons": ["auto_allowed"]}

    r = Rescue(state, probe=lambda: box["snap"], act=act, clock=clock)
    return r, clock, calls, state, box


ON = {"hung": True, "memory": True}


def test_a_program_hanging_for_three_minutes_is_restarted_once():
    r, clock, calls, _, _ = make({"mem_pct": 50.0, "total_mb": 16000, "procs": [proc(10, "Kasse.exe", hung=True)]})
    r.tick(ON)
    clock.t += HUNG_AFTER_S - 20
    r.tick(ON)
    assert calls == []  # a short freeze is left alone: the program may recover by itself
    clock.t += 20
    r.tick(ON)
    assert calls == [("windows.restart_hung_app", {"pid": 10, "name": "Kasse.exe"})]
    clock.t += 20
    r.tick(ON)
    assert len(calls) == 1  # never twice for the same hang
    ev = r.report()["events"][-1]
    assert ev["kind"] == "hung" and ev["name"] == "Kasse.exe" and ev["outcome"] == "executed_verified" and ev["secs"] >= HUNG_AFTER_S


def test_a_program_that_recovers_starts_counting_again():
    r, clock, calls, _, box = make({"mem_pct": 50.0, "total_mb": 16000, "procs": [proc(10, "Kasse.exe", hung=True)]})
    r.tick(ON)
    clock.t += 120
    box["snap"] = {"mem_pct": 50.0, "total_mb": 16000, "procs": [proc(10, "Kasse.exe")]}
    r.tick(ON)
    box["snap"] = {"mem_pct": 50.0, "total_mb": 16000, "procs": [proc(10, "Kasse.exe", hung=True)]}
    clock.t += 120
    r.tick(ON)
    assert calls == []


def test_system_programs_and_bonelia_itself_are_never_touched():
    for name in ("explorer.exe", "EXPLORER.EXE", "svchost.exe", "rustdesk.exe", "BoneliaAI-Agent.exe", "dwm.exe", "python.exe"):
        assert is_protected(name)
    assert not is_protected("EXCEL.EXE")
    r, clock, calls, _, _ = make({"mem_pct": 99.0, "total_mb": 16000,
                                  "procs": [proc(4, "explorer.exe", mb=9000, hung=True), proc(5, "rustdesk.exe", mb=8000)]})
    r.tick(ON)
    clock.t += max(HUNG_AFTER_S, MEM_HIGH_FOR_S) + 1
    r.tick(ON)
    assert calls == []


def test_switched_off_means_watch_only():
    r, clock, calls, _, _ = make({"mem_pct": 97.0, "total_mb": 16000,
                                  "procs": [proc(10, "Kasse.exe", hung=True), proc(11, "chrome.exe", mb=6000)]})
    r.tick({"hung": False, "memory": False})
    clock.t += 3600
    r.tick({"hung": False, "memory": False})
    assert calls == []
    rep = r.report()
    assert rep["hung"][0]["name"] == "Kasse.exe" and rep["mem_pct"] == 97.0  # still shown in the panel


def test_full_memory_for_ten_minutes_closes_the_biggest_program_politely_and_reopens_it():
    snap = {"mem_pct": 95.0, "total_mb": 16000,
            "procs": [proc(10, "Kasse.exe", mb=900), proc(11, "chrome.exe", mb=5200), proc(12, "LM Studio.exe", mb=300)]}
    r, clock, calls, _, _ = make(snap)
    r.tick(ON)
    clock.t += MEM_HIGH_FOR_S - 30
    r.tick(ON)
    assert calls == []  # a short peak is normal
    clock.t += 30
    r.tick(ON)
    assert calls == [("windows.close_program", {"pid": 11, "name": "chrome.exe", "restart": True})]
    clock.t += 20
    r.tick(ON)
    assert len(calls) == 1  # waits another ten minutes before the next step
    clock.t += MEM_HIGH_FOR_S
    r.tick(ON)
    # chrome was handled less than two hours ago: the next biggest program is next
    assert calls[-1] == ("windows.close_program", {"pid": 10, "name": "Kasse.exe", "restart": True})


def test_memory_drops_reset_the_wait_and_small_programs_are_not_closed():
    snap = {"mem_pct": 95.0, "total_mb": 16000, "procs": [proc(11, "notepad.exe", mb=100)]}
    r, clock, calls, _, box = make(snap)
    r.tick(ON)
    clock.t += MEM_HIGH_FOR_S + 1
    r.tick(ON)
    assert calls == []  # nothing big enough to help
    box["snap"] = {"mem_pct": 60.0, "total_mb": 16000, "procs": [proc(11, "chrome.exe", mb=5000)]}
    r.tick(ON)
    box["snap"] = {"mem_pct": 95.0, "total_mb": 16000, "procs": [proc(11, "chrome.exe", mb=5000)]}
    clock.t += 60
    r.tick(ON)
    assert calls == []


def test_a_close_request_from_the_panel_runs_once_for_the_program_it_names():
    snap = {"mem_pct": 70.0, "total_mb": 16000, "procs": [proc(11, "chrome.exe", mb=5000)]}
    r, clock, calls, state, _ = make(snap)
    req = {"id": "abc", "pid": 11, "name": "chrome.exe", "restart": False}
    r.tick(ON, req)
    r.tick(ON, req)
    assert calls == [("windows.close_program", {"pid": 11, "name": "chrome.exe", "restart": False})]
    assert r.report()["events"][-1]["kind"] == "manual" and r.report()["request_done"] == "abc"
    # a request for a program that is gone (or a different one under that number) does nothing
    r.tick(ON, {"id": "def", "pid": 11, "name": "EXCEL.EXE", "restart": True})
    assert len(calls) == 1 and r.report()["events"][-1]["outcome"] == "not_found"


def test_server_unreachable_is_retried_and_not_recorded():
    r, clock, calls, _, _ = make({"mem_pct": 50.0, "total_mb": 16000, "procs": [proc(10, "Kasse.exe", hung=True)]}, outcome="offline")
    r.tick(ON)
    clock.t += HUNG_AFTER_S + 1
    r.tick(ON)
    clock.t += 20
    r.tick(ON)
    assert len(calls) == 2 and r.report()["events"] == []


def test_report_lists_the_five_biggest_programs_for_the_panel():
    procs = [proc(i, f"app{i}.exe", mb=i * 100) for i in range(1, 9)] + [proc(99, "svchost.exe", mb=99999)]
    r, *_ = make({"mem_pct": 80.0, "total_mb": 16000, "procs": procs})
    r.tick(ON)
    top = r.report()["top"]
    assert [t["name"] for t in top] == ["app8.exe", "app7.exe", "app6.exe", "app5.exe", "app4.exe"]
    assert top[0] == {"pid": 8, "name": "app8.exe", "mb": 800}


def test_a_failing_probe_never_breaks_the_agent():
    def bad():
        raise OSError("no desktop")

    r = Rescue({}, probe=bad, act=lambda t, p: {}, clock=Clock())
    r.tick(ON)
    assert r.report()["mem_pct"] is None
