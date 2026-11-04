"""Triage of real entries seen on the owner's German Windows 11 PC (2026-11-04)."""

from bonelia.contracts import AppIdentity, DiagnosticEvent, Evidence, Severity, Triage
from bonelia.diagnostics.triage import apply_triage, classify
from bonelia.monitor.scan import _service_events


def ev(provider, eid, severity=Severity.error, occ=1, rule=None):
    return DiagnosticEvent(app=AppIdentity(app_id="x", name=provider), title=f"{provider} {eid}", fingerprint=f"{provider}{eid}",
                           severity=severity, occurrences=occ, rule_id=rule,
                           evidence=[Evidence(source="windows_event_log:System", kind="event", code=f"{provider}/{eid}")])


def test_routine_windows_noise_is_harmless():
    for prov, eid in [("Win32k", 700), ("Win32k", 701), (".NET Runtime", 1000), ("Microsoft Office 16", 2011),
                      ("Microsoft-Windows-WindowsUpdateClient", 20), ("BthMini", 16),
                      ("Microsoft-Windows-DeviceAssociationService", 3501), ("Microsoft-Windows-Kernel-Processor-Power", 37),
                      ("Microsoft-Windows-DistributedCOM", 10016)]:
        assert classify(ev(prov, eid), "tr")[0] == Triage.harmless, prov


def test_backup_related_and_one_off_crash_need_a_check_and_repeats_are_important():
    assert classify(ev("VSS", 12292, occ=22), "de")[0] == Triage.check
    assert classify(ev("Application Error", 1000, rule="win.app_crash"), "tr")[0] == Triage.check
    assert classify(ev("Application Error", 1000, occ=3, rule="win.app_crash"), "tr")[0] == Triage.important
    assert classify(ev("disk", 7, Severity.critical, rule="win.disk_error"), "tr")[0] == Triage.important
    assert classify(ev("BoneliaTest", 999), "tr")[0] == Triage.check


def test_unknown_entries():
    assert classify(ev("SomeVendor", 5, Severity.critical), "en")[0] == Triage.important
    assert classify(ev("SomeVendor", 5, Severity.error), "en")[0] == Triage.check
    assert classify(ev("SomeVendor", 5, Severity.warning), "en")[0] == Triage.harmless
    assert classify(ev("SomeVendor", 5, Severity.warning, occ=9), "en")[0] == Triage.check


def test_apply_triage_orders_important_first_and_sets_reason():
    out = apply_triage([ev("Win32k", 700), ev("VSS", 12292), ev("disk", 7, Severity.critical, rule="win.disk_error")], "tr")
    assert [e.triage for e in out] == [Triage.important, Triage.check, Triage.harmless]
    assert all(e.triage_reason for e in out)


def test_stopped_automatic_service_gets_a_one_click_repair_and_noise_is_skipped():
    svcs = [
        {"name": "PosKasseSync", "display_name": "PosKasse Sync Service", "status": "stopped", "start_type": "automatic"},
        {"name": "sppsvc", "display_name": "Software Protection", "status": "stopped", "start_type": "automatic"},
        {"name": "CDPUserSvc_4a1b2c", "display_name": "CDP User", "status": "stopped", "start_type": "automatic"},
        {"name": "RpcSs", "display_name": "RPC", "status": "stopped", "start_type": "automatic"},
        {"name": "Spooler", "display_name": "Druckwarteschlange", "status": "running", "start_type": "automatic"},
        {"name": "Fax", "display_name": "Fax", "status": "stopped", "start_type": "manual"},
    ]
    crash = ev("Service Control Manager", 7034, rule="win.service_crash", occ=3)
    crash.evidence[0].data = {"service_display_name": "Druckwarteschlange"}
    out = _service_events(svcs, [crash], "tr")
    assert [e.repair_params["service_name"] for e in out] == ["PosKasseSync"]
    assert out[0].repair_tool == "windows.start_service" and out[0].rule_id == "win.service_stopped"
    assert classify(out[0], "tr")[0] == Triage.important
    # running service that crashed repeatedly -> restart (level 2) suggestion
    assert crash.repair_tool == "windows.restart_service" and crash.repair_params == {"service_name": "Spooler"}


def test_new_signatures_are_recognised_and_triaged():
    from bonelia.collectors.windows_events import RawEvent
    from bonelia.diagnostics.engine import event_from_raw

    cases = {("MSSQLSERVER", 9002): Triage.important, ("MSSQLSERVER", 824): Triage.important,
             ("Microsoft-Windows-WHEA-Logger", 19): Triage.important, ("Microsoft-Windows-WER-SystemErrorReporting", 1001): Triage.important,
             ("Service Control Manager", 7001): Triage.check, ("volsnap", 36): Triage.check}
    for (prov, eid), expected in cases.items():
        e = event_from_raw(RawEvent(log="System", provider=prov, event_id=eid, level=2, time_created=None, message="x"), "tr")
        assert e.rule_id is not None, (prov, eid)
        assert classify(e, "tr")[0] == expected, (prov, eid)
