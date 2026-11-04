"""Tests that only prove something on a REAL Windows host (GitHub windows-latest runner or a test PC)."""

import subprocess
import sys

import pytest

pytestmark = [pytest.mark.windows, pytest.mark.skipif(sys.platform != "win32", reason="requires real Windows")]


def test_real_event_log_is_readable():
    from bonelia.collectors.windows_events import collect

    events, status = collect(hours=24 * 7, max_events=50)
    assert status["eventlog:Application"].startswith("ok:"), status
    assert status["eventlog:System"].startswith("ok:"), status
    assert all(e.event_id >= 0 for e in events)


def test_controlled_error_is_detected_in_event_log():
    from bonelia.collectors.windows_events import collect
    from bonelia.diagnostics.engine import event_from_raw

    subprocess.run(["eventcreate", "/T", "ERROR", "/ID", "998", "/L", "APPLICATION", "/SO", "BoneliaAIWinTest",
                    "/D", "BONELIA AI windows test error mail test@example.com"], check=True, capture_output=True)
    events, _ = collect(hours=1, logs=("Application",), max_events=100)
    hit = [e for e in events if e.provider == "BoneliaAIWinTest" and e.event_id == 998]
    assert hit, "controlled event not found"
    ev = event_from_raw(hit[0], "tr")
    assert ev is not None and "test@example.com" not in ev.evidence[0].text


def test_installed_apps_and_services():
    from bonelia.collectors.system import installed_apps, services

    apps, st = installed_apps()
    assert st.startswith("ok:") and apps
    svcs, st2 = services()
    assert st2.startswith("ok:") and any(s["name"].lower() == "eventlog" for s in svcs)


def test_security_log_is_never_read():
    from bonelia.collectors.windows_events import collect

    _, status = collect(hours=1, logs=("Security",))
    assert status["eventlog:Security"] == "denied:not_allowed"


def test_full_scan_on_windows():
    from bonelia.monitor.scan import run_scan

    res = run_scan(mode="quick", salt="s", lang="de")
    assert res.system.is_windows and res.collector_status["installed_apps"].startswith("ok:")


def test_german_umlauts_survive_event_log_reading():
    """Regression (owner's German Windows): 'Gerätezuordnung' was read as 'Ger�tezuordnung'."""
    from bonelia.collectors.windows_events import collect

    subprocess.run(["eventcreate", "/T", "ERROR", "/ID", "996", "/L", "APPLICATION", "/SO", "BoneliaAIUmlaut",
                    "/D", "Fehler bei der Gerätezuordnung: Größe Ä Ö Ü ß"], check=True, capture_output=True)
    events, status = collect(hours=1, logs=("Application",), max_events=100)
    assert status["eventlog:Application"].startswith("ok:"), status
    hit = [e for e in events if e.provider == "BoneliaAIUmlaut"]
    assert hit and "Gerätezuordnung" in hit[0].message and "�" not in hit[0].message, hit[0].message if hit else events[:3]
