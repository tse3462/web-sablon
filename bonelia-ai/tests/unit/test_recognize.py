from bonelia.collectors.windows_events import parse_rendered_events
from bonelia.contracts import AppIdentity
from bonelia.diagnostics.engine import event_from_raw
from bonelia.diagnostics.recognize import correlate, match_installed, normalize
from tests.conftest import fixture_text

INSTALLED = [
    AppIdentity(app_id="win:poskasse pro 4", name="PosKasse Pro 4", publisher="Kassen GmbH", version="4.2.1.0"),
    AppIdentity(app_id="win:microsoft edge", name="Microsoft Edge", publisher="Microsoft Corporation", version="130.0"),
    AppIdentity(app_id="win:sap business one client (64-bit)", name="SAP Business One Client (64-bit)", publisher="SAP", version="10.0"),
]


def test_normalize():
    assert normalize("PosKasse.exe") == "poskasse"
    assert normalize("SAP Business One Client (64-bit)") == "sapbusinessoneclient"


def test_match_unknown_software_by_executable_name():
    assert match_installed("PosKasse.exe", INSTALLED).publisher == "Kassen GmbH"
    assert match_installed("msedge.exe", INSTALLED) is None  # no false positive on unrelated names
    assert match_installed("abc", INSTALLED) is None  # too short to be meaningful
    assert match_installed("SAP Business One Client.exe", INSTALLED).publisher == "SAP"


def test_correlate_enriches_events_without_app_specific_code():
    raw = parse_rendered_events(fixture_text("app_error_events.xml"), "Application")
    events = [e for e in (event_from_raw(r, "tr") for r in raw) if e]
    correlate(events, INSTALLED)
    crash = events[0]
    assert crash.app.publisher == "Kassen GmbH" and crash.app.name == "PosKasse Pro 4 (PosKasse.exe)"
    assert crash.app.version == "4.2.1.0"
    assert correlate(events, []) is events
