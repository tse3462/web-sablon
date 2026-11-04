"""Scan orchestration on the customer machine (read-only)."""

from __future__ import annotations

from pathlib import Path

from ..adapters.generic_windows import filter_apps
from ..collectors import health, log_files, system, windows_events
from ..contracts import AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, ScanResult, Severity, utcnow
from ..diagnostics.engine import diagnose_with_rules, event_from_raw, group_events, metric_events
from ..diagnostics.health_rules import backup_events, disk_health_events
from ..diagnostics.recognize import correlate
from ..diagnostics.triage import apply_triage
from ..repair.windows_tools import CRITICAL_SERVICES, NORMALLY_STOPPED
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


_STOPPED_TITLE = {"tr": "Hizmet durmuş: {n}", "de": "Dienst gestoppt: {n}", "en": "Service stopped: {n}"}


def _service_events(svcs: list[dict], events: list[DiagnosticEvent], lang: str) -> list[DiagnosticEvent]:
    """Stopped automatic services + repair suggestions (start / restart) for service problems."""
    import hashlib

    by_display = {str(s.get("display_name") or "").lower(): s for s in svcs}
    out: list[DiagnosticEvent] = []
    for s in svcs:
        name, status, start = str(s.get("name") or ""), s.get("status"), s.get("start_type")
        if start != "automatic" or status != "stopped" or not name:
            continue
        if name.lower() in NORMALLY_STOPPED or name.lower() in CRITICAL_SERVICES or "_" in name and name.split("_")[-1].isalnum() and len(name.split("_")[-1]) >= 5:
            continue  # per-user service instances (Name_1a2b3c) and Windows' own trigger-start services
        display = str(s.get("display_name") or name)[:150]
        out.append(DiagnosticEvent(
            app=AppIdentity(app_id=f"svc:{name.lower()}", name=display, adapter_id="generic-windows"),
            category=ErrorCategory.service_failure, severity=Severity.error, title=_STOPPED_TITLE[lang].format(n=display),
            fingerprint=hashlib.sha256(f"svc-stopped|{name.lower()}".encode()).hexdigest()[:32], rule_id="win.service_stopped",
            evidence=[Evidence(source="windows_services", kind="service_state", code="BONELIA:services/0",
                               data={"service_name": name, "status": status, "start_type": start})],
            repair_tool="windows.start_service", repair_params={"service_name": name}))
    # Repair suggestions for Service Control Manager crash events
    for ev in events:
        if ev.rule_id not in ("win.service_crash", "win.service_start_failed"):
            continue
        disp = next((e.data.get("service_display_name") for e in ev.evidence if e.data.get("service_display_name")), None)
        s = by_display.get(str(disp or "").lower())
        if not s or str(s.get("name", "")).lower() in CRITICAL_SERVICES:
            continue
        if s.get("status") == "stopped" and s.get("start_type") != "disabled":
            ev.repair_tool, ev.repair_params = "windows.start_service", {"service_name": s["name"]}
        elif s.get("status") == "running" and ev.occurrences >= 2:
            ev.repair_tool, ev.repair_params = "windows.restart_service", {"service_name": s["name"]}
    return out


def attach_generic_repairs(events: list[DiagnosticEvent], snap) -> list[DiagnosticEvent]:
    """Deterministic repair suggestions (never chosen by the AI)."""
    import os

    sys_drive = (os.environ.get("SystemDrive", "C:") + "\\").upper()
    for ev in events:
        if ev.repair_tool:
            continue
        if ev.rule_id == "win.dns_timeout":
            ev.repair_tool, ev.repair_params = "windows.flush_dns", {}
        elif ev.rule_id == "metric.disk_full" and snap is not None and snap.is_windows:
            mount = next((str(e.data.get("mount", "")) for e in ev.evidence if e.data.get("mount")), "")
            if mount.upper() == sys_drive:
                ev.repair_tool, ev.repair_params = "windows.clean_temp", {}
    return events


def run_scan(mode: str = "quick", salt: str = "", lang: str = "tr", app_query: str | None = None,
             log_paths: list[str] | None = None, hours: int | None = None, include_eventlog: bool = True,
             backup_policy: dict | None = None, include_health: bool = True) -> ScanResult:
    if mode not in MODES:
        raise ValueError(f"unknown scan mode: {mode}")
    res = ScanResult(mode=mode)
    res.system = system.snapshot(salt)
    res.collector_status["system"] = "ok"

    all_apps, st = system.installed_apps()
    res.collector_status["installed_apps"] = st
    apps = filter_apps(all_apps, app_query) if app_query else all_apps
    res.apps = apps[:300]

    if include_eventlog:
        raw, st_ev = windows_events.collect(hours=hours or MODES[mode])
        res.collector_status.update(st_ev)
    else:
        raw = []
        res.collector_status["eventlog"] = "skipped:by_operator"
    events = correlate([e for e in (event_from_raw(r, lang) for r in raw) if e is not None], all_apps)
    if app_query:
        q = app_query.lower()
        events = [e for e in events if q in e.app.name.lower() or any(q in ev.text.lower() for ev in e.evidence)]
    events.extend(metric_events(res.system, lang))
    if include_health and res.system.is_windows:  # disk health + backup freshness (cached, read-only)
        disks, st_disk = health.cached_disk_health()
        res.collector_status["disk_health"] = st_disk
        events.extend(disk_health_events(disks, lang))
        bstate, st_bak = health.cached_backup_state(backup_policy)
        res.collector_status["backup"] = st_bak
        events.extend(backup_events(backup_policy, bstate, lang))
    if include_eventlog:
        svcs, st_svc = system.services()
        res.collector_status["services"] = st_svc
        events.extend(_service_events(svcs, events, lang))
    lf_events, lf_status = _log_file_events(log_paths or [], lang)
    events.extend(lf_events)
    res.collector_status.update(lf_status)

    res.events = apply_triage(attach_generic_repairs(group_events(events), res.system), lang)
    res.diagnoses = [diagnose_with_rules(e, lang) for e in res.events]
    res.finished_at = utcnow()
    return res
