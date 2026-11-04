"""Scan orchestration on the customer machine (read-only)."""

from __future__ import annotations

from pathlib import Path

from ..adapters.generic_windows import filter_apps
from ..collectors import log_files, system, windows_events
from ..contracts import AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, ScanResult, Severity, utcnow
from ..diagnostics.engine import diagnose_with_rules, event_from_raw, group_events, metric_events
from ..security.redact import redact_text

MODES = {"quick": 24, "full": 24 * 7, "recent": 1, "app": 24 * 7}


def _log_file_events(paths: list[str], lang: str) -> tuple[list[DiagnosticEvent], dict[str, str]]:
    events: list[DiagnosticEvent] = []
    status: dict[str, str] = {}
    for p in paths[:10]:
        lines, st = log_files.tail_error_lines(Path(p))
        status[f"logfile:{Path(p).name}"] = st
        if not lines:
            continue
        app = AppIdentity(app_id=f"file:{Path(p).stem.lower()[:80]}", name=Path(p).stem[:200])
        import hashlib

        for line in lines[-50:]:
            normalized = redact_text(line, 500)
            # fingerprint on the line with digits removed so timestamps don't defeat grouping
            key = "".join(ch for ch in normalized if not ch.isdigit())[:200]
            fp = hashlib.sha256(f"logfile|{p}|{key}".encode()).hexdigest()[:32]
            events.append(DiagnosticEvent(
                app=app, category=ErrorCategory.unknown, severity=Severity.error,
                title={"tr": "Uygulama günlüğünde hata", "de": "Fehler im Anwendungsprotokoll", "en": "Error in application log"}[lang],
                fingerprint=fp, evidence=[Evidence(source=f"logfile:{Path(p).name}", kind="log_line", text=normalized, redacted=True)]))
    return events, status


def run_scan(mode: str = "quick", salt: str = "", lang: str = "tr", app_query: str | None = None,
             log_paths: list[str] | None = None, hours: int | None = None, include_eventlog: bool = True) -> ScanResult:
    if mode not in MODES:
        raise ValueError(f"unknown scan mode: {mode}")
    res = ScanResult(mode=mode)
    res.system = system.snapshot(salt)
    res.collector_status["system"] = "ok"

    apps, st = system.installed_apps()
    res.collector_status["installed_apps"] = st
    if app_query:
        apps = filter_apps(apps, app_query)
    res.apps = apps[:300]

    if include_eventlog:
        raw, st_ev = windows_events.collect(hours=hours or MODES[mode])
        res.collector_status.update(st_ev)
    else:
        raw = []
        res.collector_status["eventlog"] = "skipped:by_operator"
    events = [e for e in (event_from_raw(r, lang) for r in raw) if e is not None]
    if app_query:
        q = app_query.lower()
        events = [e for e in events if q in e.app.name.lower() or any(q in ev.text.lower() for ev in e.evidence)]
    events.extend(metric_events(res.system, lang))
    lf_events, lf_status = _log_file_events(log_paths or [], lang)
    events.extend(lf_events)
    res.collector_status.update(lf_status)

    res.events = group_events(events)
    res.diagnoses = [diagnose_with_rules(e, lang) for e in res.events]
    res.finished_at = utcnow()
    return res
