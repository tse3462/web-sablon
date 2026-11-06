"""The watcher's report (written by a user-session process, so untrusted) and its stop rule."""

import json
import os
import time

from bonelia.collectors.programs import ALIVE_STALE_S, STATES_FRESH_S, parse_states, read_states, session_watch


def test_only_clean_process_numbers_and_flags_are_taken():
    raw = {"states": {"10": True, "11": False, "x": True, "-1": True, "12": "yes", "99999999999": True}}
    assert parse_states(raw) == {10: True, 11: False}
    assert parse_states(["no"]) == {} and parse_states({"states": 5}) == {}


def test_an_old_or_broken_report_counts_as_no_report(tmp_path):
    f = tmp_path / "windows-1.json"
    f.write_text(json.dumps({"states": {"10": True}}))
    now = time.time()
    assert read_states(f, now) == {10: True}
    os.utime(f, (now - STATES_FRESH_S - 5, now - STATES_FRESH_S - 5))
    assert read_states(f, now) is None
    f.write_text("{broken")
    assert read_states(f, time.time()) is None
    assert read_states(tmp_path / "missing.json") is None


def test_the_watcher_writes_its_report_and_stops_when_the_agent_is_gone(tmp_path):
    alive = tmp_path / "agent.alive"
    alive.write_text("1")
    d = tmp_path / "1-abc"
    d.mkdir()
    rc = session_watch(d, alive, window_states=lambda: {10: True, 11: False}, rounds=2, sleep=lambda s: None)
    assert rc == 0
    assert parse_states(json.loads((d / "windows.json").read_text())) == {10: True, 11: False}
    old = time.time() - ALIVE_STALE_S - 10
    os.utime(alive, (old, old))
    (d / "windows.json").unlink()
    session_watch(d, alive, window_states=lambda: {10: True}, rounds=5, sleep=lambda s: None)
    assert not (d / "windows.json").exists()  # stopped at once


def test_a_second_watcher_in_the_same_session_stops_at_once(tmp_path):
    alive = tmp_path / "agent.alive"
    alive.write_text("1")
    session_watch(tmp_path, alive, window_states=lambda: {10: True}, rounds=3, sleep=lambda s: None, single=lambda: False)
    assert not (tmp_path / "windows.json").exists()


def test_oversized_odd_or_linked_reports_are_refused(tmp_path):
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"states": {str(i): True for i in range(1, 30000)}}))
    assert read_states(big, time.time()) is None  # over 256 KB
    assert parse_states({"states": {"\u00b2": True, "12345678901": True, "7": True}}) == {7: True}
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"states": {"10": True}}))
    link = tmp_path / "link.json"
    link.symlink_to(real)
    assert read_states(link, time.time()) is None


def test_the_watcher_command_exists_and_stops_without_an_agent(tmp_path):
    from bonelia.monitor.cli import main

    assert main(["session-watch", "--dir", str(tmp_path), "--alive", str(tmp_path / "agent.alive")]) == 0
