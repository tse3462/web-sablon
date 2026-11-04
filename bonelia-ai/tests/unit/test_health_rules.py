"""Disk health and backup freshness: findings, triage, advice (no Windows needed)."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from bonelia.collectors.health import folder_state
from bonelia.contracts import Triage
from bonelia.diagnostics.engine import diagnose_with_rules
from bonelia.diagnostics.health_rules import backup_events, disk_health_events
from bonelia.diagnostics.triage import apply_triage

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
HEALTHY = {"name": "Samsung SSD 870", "media": "SSD", "health": "Healthy", "wear": 3, "temperature": 38,
           "read_errors": 0, "write_errors": 0}


def rules(events):
    return sorted(e.rule_id for e in events)


def triaged(events):
    return {e.rule_id: e.triage for e in apply_triage(events, "tr")}


def test_healthy_disk_gives_no_finding():
    assert disk_health_events({"disks": [HEALTHY], "predict_failure": []}) == []
    # missing counters (non-admin / unsupported disk) are not treated as problems
    assert disk_health_events({"disks": [{"name": "X", "health": "Healthy", "wear": None, "temperature": None}]}) == []


def test_failing_disk_is_important_and_explained():
    evs = disk_health_events({"disks": [{**HEALTHY, "health": "Warning", "read_errors": 4}]}, "tr")
    assert rules(evs) == ["disk.health_failing", "disk.uncorrected_errors"]
    t = triaged(evs)
    assert t["disk.health_failing"] == Triage.important and t["disk.uncorrected_errors"] == Triage.important
    d = diagnose_with_rules(evs[0], "tr")
    assert "bozulmaya" in d.hypotheses[0].cause and any("yedeğini" in r.description for r in d.recommendations)
    assert all(not e.repair_tool for e in evs)  # never an automatic action for a failing disk


def test_smart_prediction_wear_and_heat():
    evs = disk_health_events({"disks": [{**HEALTHY, "wear": 93}, {**HEALTHY, "name": "WD Blue", "wear": 84, "temperature": 71}],
                              "predict_failure": ["SCSI\\Disk&Ven_WDC\\0"]}, "tr")
    assert rules(evs) == ["disk.health_failing", "disk.hot", "disk.wear_high", "disk.wear_warn"]
    t = triaged(evs)
    assert t["disk.wear_high"] == Triage.important and t["disk.health_failing"] == Triage.important
    assert t["disk.wear_warn"] == Triage.check and t["disk.hot"] == Triage.check


def test_backup_folder_missing_empty_stale_and_fresh():
    state = {"folders": [
        {"path": "E:\\Yedek", "exists": False, "files": 0, "newest": None},
        {"path": "D:\\Bos", "exists": True, "files": 0, "newest": None},
        {"path": "D:\\Kasa\\Yedek", "exists": True, "files": 9, "newest": (NOW - timedelta(days=5)).isoformat()},
        {"path": "D:\\Taze", "exists": True, "files": 3, "newest": (NOW - timedelta(hours=20)).isoformat()},
    ], "windows": {"status": "not_found"}}
    evs = backup_events({"paths": ["..."], "max_age_days": 2}, state, "tr", now=NOW)
    assert rules(evs) == ["backup.empty", "backup.folder_missing", "backup.stale"]
    assert all(v == Triage.important for v in triaged(evs).values())
    stale = next(e for e in evs if e.rule_id == "backup.stale")
    assert "5 gün önce" in stale.title and "harici disk" in next(e for e in evs if e.rule_id == "backup.folder_missing").title
    # the finding's identity does not change every day, so it is reported once, not daily
    later = backup_events({"max_age_days": 2}, {**state, "folders": state["folders"][2:3]}, "tr", now=NOW + timedelta(days=3))
    assert later[0].fingerprint == stale.fingerprint and "8 gün önce" in later[0].title


def test_windows_backup_detection():
    fresh = {"status": "ok", "last_success": (NOW - timedelta(days=3)).isoformat(), "last_event": NOW.isoformat()}
    assert backup_events(None, {"folders": [], "windows": fresh}, now=NOW) == []  # weekly Windows Backup is fine
    old = {**fresh, "last_success": (NOW - timedelta(days=12)).isoformat()}
    assert rules(backup_events(None, {"folders": [], "windows": old}, now=NOW)) == ["backup.windows_stale"]
    failing = {"status": "ok", "last_success": None, "last_event": NOW.isoformat()}
    assert rules(backup_events(None, {"folders": [], "windows": failing}, now=NOW)) == ["backup.windows_failing"]


def test_no_backup_at_all_is_a_quiet_hint_not_an_alarm():
    for st in ("ok", "not_found"):
        evs = backup_events(None, {"folders": [], "windows": {"status": st, "last_success": None, "last_event": None}}, now=NOW)
        assert rules(evs) == ["backup.none"] and triaged(evs)["backup.none"] == Triage.check  # panel only, no phone alert
    # unknown state (query error) must not claim "no backup"
    assert backup_events(None, {"folders": [], "windows": {"status": "error:TimeoutExpired"}}, now=NOW) == []
    # a configured folder replaces the hint
    ok = {"folders": [{"path": "D:\\Y", "exists": True, "files": 1, "newest": NOW.isoformat()}], "windows": {"status": "not_found"}}
    assert backup_events({"paths": ["D:\\Y"]}, ok, now=NOW) == []


def test_policy_age_limit_is_clamped():
    state = {"folders": [{"path": "D:\\Y", "exists": True, "files": 1, "newest": (NOW - timedelta(days=3)).isoformat()}],
             "windows": {"status": "not_found"}}
    assert rules(backup_events({"max_age_days": 0}, state, now=NOW)) == ["backup.stale"]  # 0 -> 1 day
    assert backup_events({"max_age_days": 999}, state, now=NOW) == []  # 999 -> 60 days
    assert rules(backup_events({"max_age_days": "x"}, state, now=NOW)) == ["backup.stale"]  # invalid -> default 2


def test_folder_state_reads_timestamps_only(tmp_path):
    assert folder_state(str(tmp_path / "missing")) == {"path": str(tmp_path / "missing"), "exists": False, "files": 0, "newest": None}
    empty = tmp_path / "empty"
    empty.mkdir()
    assert folder_state(str(empty))["exists"] is True and folder_state(str(empty))["files"] == 0
    root = tmp_path / "backup"
    (root / "2026" / "11").mkdir(parents=True)
    old, new = root / "old.bak", root / "2026" / "11" / "kasa.bak"
    old.write_text("x")
    new.write_text("y")
    week_ago = time.time() - 7 * 86400
    os.utime(old, (week_ago, week_ago))
    st = folder_state(str(root))
    assert st["files"] == 2 and datetime.fromisoformat(st["newest"]) > datetime.now(timezone.utc) - timedelta(minutes=5)
    deep = root / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / "too-deep.bak").write_text("z")
    assert folder_state(str(root), max_depth=2)["files"] == 2  # bounded walk
    assert folder_state(str(old))["files"] == 1  # a single backup file works too
