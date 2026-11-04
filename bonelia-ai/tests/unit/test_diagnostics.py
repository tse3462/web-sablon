from datetime import datetime, timezone
from pathlib import Path

from bonelia.collectors.log_files import tail_error_lines
from bonelia.collectors.windows_events import build_query, parse_rendered_events
from bonelia.contracts import Confidence, ErrorCategory, Severity, SystemSnapshot
from bonelia.diagnostics.engine import diagnose_with_rules, event_from_raw, group_events, metric_events
from tests.conftest import fixture_text


def _events(lang="tr"):
    raw = parse_rendered_events(fixture_text("app_error_events.xml"), "Application")
    return raw, [e for e in (event_from_raw(r, lang) for r in raw) if e]


def test_parse_rendered_xml():
    raw, _ = _events()
    assert len(raw) == 5
    crash = raw[0]
    assert crash.provider == "Application Error" and crash.event_id == 1000 and crash.level == 2
    assert crash.time_created == datetime(2026, 11, 3, 21, 14, 5, 123456, tzinfo=timezone.utc)
    assert crash.data[0] == "PosKasse.exe"
    assert all(r.time_created.tzinfo is not None for r in raw)


def test_parser_survives_corrupt_and_truncated_xml():
    good = fixture_text("app_error_events.xml")
    broken = good[: len(good) // 2] + "<<<garbage &&& </Event>"
    raw = parse_rendered_events(broken, "Application")
    assert 1 <= len(raw) < 5
    assert parse_rendered_events("", "Application") == []
    assert parse_rendered_events("not xml at all", "Application") == []


def test_info_events_are_ignored_and_crash_is_classified():
    _, evs = _events()
    assert len(evs) == 4  # level-4 info event dropped
    crash = evs[0]
    assert crash.category == ErrorCategory.app_crash and crash.rule_id == "win.app_crash"
    assert crash.app.name == "PosKasse.exe" and crash.app.version == "4.2.1.0"
    ev = crash.evidence[0]
    assert ev.data["exception_code"] == "0xc0000005" and ev.data["faulting_module"] == "printdrv.dll"
    # personal data in the rendered message is redacted
    assert "mueller" not in ev.text and "anna.mueller@firma.de" not in ev.text and "3f2b9c1e" not in ev.text


def test_grouping_collapses_repeated_crashes():
    _, evs = _events()
    grouped = group_events(evs)
    crash = next(e for e in grouped if e.rule_id == "win.app_crash")
    assert crash.occurrences == 2 and len(grouped) == 3


def test_rules_diagnosis_is_never_definitive_and_mentions_exception():
    _, evs = _events("de")
    d = diagnose_with_rules(group_events(evs)[0], "de")
    assert d.is_definitive is False and d.produced_by == "rules"
    assert any("0xc0000005" in h.cause and "printdrv.dll" in h.cause for h in d.hypotheses)
    assert all(r.manual for r in d.recommendations)


def test_service_crash_and_unknown_event():
    _, evs = _events("en")
    svc = next(e for e in evs if e.rule_id == "win.service_crash")
    assert svc.category == ErrorCategory.service_failure
    unknown = next(e for e in evs if e.rule_id is None)
    d = diagnose_with_rules(unknown, "en")
    assert d.hypotheses[0].confidence == Confidence.low and d.missing_information


def test_prompt_injection_in_log_is_flagged_and_secret_redacted():
    _, evs = _events("tr")
    inj = next(e for e in evs if e.app.name == "CustomVendorApp")
    assert "Hunter22!" not in inj.evidence[0].text
    d = diagnose_with_rules(inj, "tr")
    assert any("prompt injection" in w for w in d.warnings)
    assert all(r.tool_id is None for r in d.recommendations)


def test_metric_events():
    snap = SystemSnapshot(hostname_ref="ref_x", os="Windows", os_version="10", memory_used_percent=95.0,
                          disks=[{"mount": "C:\\", "used_percent": 98.0}, {"mount": "D:\\", "used_percent": 40.0}], is_windows=True)
    evs = metric_events(snap, "tr")
    assert {e.rule_id for e in evs} == {"metric.disk_full", "metric.memory_high"}
    assert next(e for e in evs if e.rule_id == "metric.disk_full").severity == Severity.critical


def test_query_bounds():
    q = build_query(10_000)
    assert "Level=1 or Level=2 or Level=3" in q and str(30 * 24 * 3600 * 1000) in q


def test_log_tail_is_bounded(tmp_path: Path):
    p = tmp_path / "app.log"
    with open(p, "w", encoding="utf-8") as fh:
        for i in range(200_000):
            fh.write(f"2026-11-03 line {i} ok\n")
        fh.write("2026-11-03 ERROR database connection refused\n")
    lines, st = tail_error_lines(p, max_bytes=64 * 1024)
    assert st == "ok:1" and "connection refused" in lines[0]
    (tmp_path / "evil.exe").write_bytes(b"MZ")
    assert tail_error_lines(tmp_path / "evil.exe")[1] == "denied:suffix"
    assert tail_error_lines(tmp_path / "missing.log")[1] == "error:not_found"
    bad = tmp_path / "bin.log"
    bad.write_bytes(b"\xff\xfe\x00 fatal \x00\x81 error")
    assert tail_error_lines(bad)[1] == "ok:1"
