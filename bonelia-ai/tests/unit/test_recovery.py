"""Recovery operations: safe validation, confirm-gating, non-Windows behaviour."""

from bonelia.recovery import windows_recovery as wr


def test_operations_are_a_fixed_safe_set():
    assert set(wr.OPERATIONS) == {"restore_points", "disk_health", "pending_reboot", "sfc", "dism", "chkdsk", "restore"}
    assert wr.OPERATIONS["restore_points"]["readonly"] and not wr.OPERATIONS["sfc"]["readonly"]


def test_chkdsk_validates_drive_and_requires_confirm():
    assert wr.schedule_chkdsk("C:", confirm=False).data["needs_confirm"]
    assert wr.schedule_chkdsk("not a drive", confirm=True).error == "invalid_drive"
    assert wr.schedule_chkdsk("C:;del", confirm=True).error == "invalid_drive"


def test_restore_validates_sequence_and_requires_confirm():
    assert wr.restore_to_point(12, confirm=False).data["needs_confirm"]
    assert wr.restore_to_point(-1, confirm=True).error == "invalid_sequence"
    assert wr.restore_to_point("5; shutdown", confirm=True).error == "invalid_sequence"
    assert wr.restore_to_point(True, confirm=True).error == "invalid_sequence"


def test_readonly_and_repair_ops_report_not_windows_off_windows():
    import sys

    if sys.platform == "win32":
        return
    for name in ("restore_points", "disk_health", "sfc", "dism"):
        assert wr.OPERATIONS[name]["fn"]({}).error == "not_windows"


def test_bootrec_guide_has_all_languages():
    for lang in ("tr", "de", "en"):
        assert any("bootrec" in line for line in wr.BOOTREC_GUIDE[lang])
