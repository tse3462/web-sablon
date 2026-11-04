"""Deterministic (rule-based) diagnostic engine — works fully offline.

Pipeline (Master prompt §12): observe -> collect evidence -> identify app ->
compare with history (fingerprint grouping) -> hypotheses -> missing info ->
recommendations. The rules never claim certainty (`is_definitive=False`).
"""

from __future__ import annotations

import hashlib
import re
from collections import OrderedDict

from ..collectors.windows_events import RawEvent
from ..contracts import (
    AppIdentity,
    Confidence,
    Diagnosis,
    DiagnosticEvent,
    ErrorCategory,
    Evidence,
    Hypothesis,
    RecommendedAction,
    Severity,
    SystemSnapshot,
    utcnow,
)
from ..security.redact import redact_text
from ..security.untrusted import injection_suspected
from .knowledge import EXCEPTION_CODES, SIGNATURES, find_signature

_EXC_RE = re.compile(r"0x[0-9a-fA-F]{8}")
_LEVEL_SEVERITY = {1: Severity.critical, 2: Severity.error, 3: Severity.warning}


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(p.lower() for p in parts).encode("utf-8")).hexdigest()[:32]


def _crash_details(raw: RawEvent) -> dict[str, str]:
    """Application Error 1000 EventData layout: app, app ver, ts, module, module ver, ts, exc code, offset..."""
    d = raw.data
    out: dict[str, str] = {}
    if raw.event_id == 1000 and len(d) >= 7:
        out = {"faulting_app": d[0], "app_version": d[1], "faulting_module": d[3], "module_version": d[4],
               "exception_code": d[6].lower() if d[6] else ""}
    elif raw.event_id == 1002 and len(d) >= 2:
        out = {"faulting_app": d[0], "app_version": d[1]}
    else:
        m = _EXC_RE.search(raw.message or "")
        if m:
            out["exception_code"] = m.group(0).lower()
    exc = out.get("exception_code", "").strip().lower()
    if exc and not exc.startswith("0x") and re.fullmatch(r"[0-9a-f]{8}", exc):
        out["exception_code"] = "0x" + exc
    # These fields are technical identifiers (exe/dll names, versions, hex codes); redaction would
    # only destroy them, but we still strip anything that is not a plain identifier.
    return {k: re.sub(r"[^\w.\-+ ()]", "_", v)[:200] for k, v in out.items() if v}


def _app_for(raw: RawEvent, details: dict[str, str]) -> AppIdentity:
    name = details.get("faulting_app") or raw.provider or "unknown"
    return AppIdentity(app_id=f"win:{name.lower()[:100]}", name=name[:200], version=details.get("app_version"),
                       adapter_id="generic-windows", recognized=False)


def event_from_raw(raw: RawEvent, lang: str = "tr") -> DiagnosticEvent | None:
    if raw.level not in _LEVEL_SEVERITY:
        return None
    sig = find_signature(raw.provider, raw.event_id)
    details = _crash_details(raw)
    app = _app_for(raw, details)
    message = redact_text(raw.message, 3000)
    evidence = [Evidence(source=f"windows_event_log:{raw.log}", kind="event", observed_at=raw.time_created,
                         code=f"{raw.provider}/{raw.event_id}", text=message, data=details, redacted=True)]
    if sig:
        title = sig.title.get(lang, sig.title["en"])
        category, severity, rule_id = sig.category, sig.severity, sig.rule_id
    else:
        first = (message.split(".")[0] or f"{raw.provider} {raw.event_id}")[:200]
        title = f"{raw.provider} {raw.event_id}: {first}"
        category, severity, rule_id = ErrorCategory.unknown, _LEVEL_SEVERITY[raw.level], None
    fp = _fingerprint(raw.log, raw.provider, str(raw.event_id), details.get("faulting_app", ""),
                      details.get("faulting_module", ""), details.get("exception_code", ""))
    return DiagnosticEvent(app=app, category=category, severity=severity, title=title[:300],
                           occurred_at=raw.time_created or utcnow(), fingerprint=fp, evidence=evidence, rule_id=rule_id)


def group_events(events: list[DiagnosticEvent], max_groups: int = 100) -> list[DiagnosticEvent]:
    """Alarm grouping: identical fingerprints collapse into one event with a count."""
    groups: OrderedDict[str, DiagnosticEvent] = OrderedDict()
    for ev in sorted(events, key=lambda e: e.occurred_at, reverse=True):
        g = groups.get(ev.fingerprint)
        if g is None:
            if len(groups) >= max_groups:
                continue
            groups[ev.fingerprint] = ev.model_copy(deep=True)
        else:
            g.occurrences += ev.occurrences
            if len(g.evidence) < 3:
                g.evidence.extend(ev.evidence[:1])
    sev_rank = {Severity.critical: 0, Severity.error: 1, Severity.warning: 2, Severity.info: 3}
    return sorted(groups.values(), key=lambda e: (sev_rank[e.severity], -e.occurrences))


def metric_events(snap: SystemSnapshot, lang: str = "tr") -> list[DiagnosticEvent]:
    out: list[DiagnosticEvent] = []
    host = AppIdentity(app_id="system", name="Windows" if snap.is_windows else snap.os, version=snap.os_version[:80],
                       adapter_id="generic-windows", recognized=True)
    titles = {
        "disk": {"tr": "Disk alanı kritik seviyede", "de": "Speicherplatz kritisch", "en": "Disk space critically low"},
        "mem": {"tr": "Bellek kullanımı çok yüksek", "de": "Arbeitsspeicherauslastung sehr hoch", "en": "Memory usage very high"},
    }
    for disk in snap.disks:
        if disk.get("used_percent", 0) >= 90:
            out.append(DiagnosticEvent(
                app=host, category=ErrorCategory.disk, severity=Severity.warning if disk["used_percent"] < 97 else Severity.critical,
                title=f"{titles['disk'][lang]} ({disk.get('mount')}: %{disk.get('used_percent')})", fingerprint=_fingerprint("metric", "disk", str(disk.get("mount"))), rule_id="metric.disk_full",
                evidence=[Evidence(source="system_metrics", kind="metric", code="disk_used_percent", data=dict(disk))]))
    if (snap.memory_used_percent or 0) >= 92:
        out.append(DiagnosticEvent(
            app=host, category=ErrorCategory.resource_exhaustion, severity=Severity.warning, title=titles["mem"][lang],
            fingerprint=_fingerprint("metric", "memory"), rule_id="metric.memory_high",
            evidence=[Evidence(source="system_metrics", kind="metric", code="memory_used_percent",
                               data={"memory_used_percent": snap.memory_used_percent, "memory_total_mb": snap.memory_total_mb})]))
    return out


_GENERIC_MISSING = {
    "tr": ["Hatanın tam olarak ne zaman ve hangi işlem sırasında oluştuğu", "Uygulamanın kendi günlük dosyaları (izin verilirse)"],
    "de": ["Genauer Zeitpunkt und ausgeführte Aktion", "Eigene Protokolldateien der Anwendung (falls freigegeben)"],
    "en": ["Exact time and the action being performed", "The application's own log files (if authorised)"],
}

_RULE_NOTE = {
    "tr": "Kural tabanlı ön değerlendirme — kesin teşhis değildir.",
    "de": "Regelbasierte Vorabbewertung — keine gesicherte Diagnose.",
    "en": "Rule-based preliminary assessment — not a definitive diagnosis.",
}


def diagnose_with_rules(event: DiagnosticEvent, lang: str = "tr") -> Diagnosis:
    sig = next((s for s in SIGNATURES if s.rule_id == event.rule_id), None)
    hypotheses: list[Hypothesis] = []
    recs: list[RecommendedAction] = []
    missing: list[str] = []
    warnings: list[str] = []
    ev_codes = [e.code or e.kind for e in event.evidence][:5]
    exc = next((e.data.get("exception_code") for e in event.evidence if e.data.get("exception_code")), None)
    module = next((e.data.get("faulting_module") for e in event.evidence if e.data.get("faulting_module")), None)

    if sig:
        for cause, conf in sig.causes:
            hypotheses.append(Hypothesis(cause=cause.get(lang, cause["en"]), confidence=conf, supporting_evidence=ev_codes))
        recs = [RecommendedAction(description=a.get(lang, a["en"]), manual=True) for a in sig.actions]
        missing = [m.get(lang, m["en"]) for m in sig.missing]
    elif event.rule_id == "metric.disk_full":
        hypotheses.append(Hypothesis(cause={"tr": "Disk dolmak üzere; uygulamalar yazamayabilir", "de": "Datenträger fast voll; Schreibfehler möglich",
                                            "en": "Disk almost full; applications may fail to write"}[lang],
                                     confidence=Confidence.high, supporting_evidence=ev_codes))
        recs.append(RecommendedAction(description={"tr": "Geçici dosyaları ve büyük günlükleri yetkili kişiyle temizleyin",
                                                   "de": "Temporäre Dateien und große Logs mit befugter Person bereinigen",
                                                   "en": "Clean temporary files and large logs with an authorised person"}[lang]))
    elif event.rule_id == "metric.memory_high":
        hypotheses.append(Hypothesis(cause={"tr": "Bellek tüketimi yüksek; donma ve çökme riski", "de": "Hoher Speicherverbrauch; Hänger möglich",
                                            "en": "High memory consumption; risk of hangs and crashes"}[lang],
                                     confidence=Confidence.medium, supporting_evidence=ev_codes))
    else:
        hypotheses.append(Hypothesis(cause={"tr": "Bilinen bir imza ile eşleşmedi; ayrıntılı analiz gerekli",
                                            "de": "Keine bekannte Signatur; tiefere Analyse nötig",
                                            "en": "No known signature matched; deeper analysis required"}[lang],
                                     confidence=Confidence.low, supporting_evidence=ev_codes))
        missing = list(_GENERIC_MISSING[lang])

    if exc and exc in EXCEPTION_CODES:
        hypotheses.insert(0, Hypothesis(cause=f"{exc}: {EXCEPTION_CODES[exc].get(lang)}" + (f" — {module}" if module else ""),
                                        confidence=Confidence.medium, supporting_evidence=ev_codes))
    if event.occurrences >= 3:
        warnings.append({"tr": f"Bu hata {event.occurrences} kez tekrarlandı", "de": f"Fehler trat {event.occurrences}× auf",
                         "en": f"This error repeated {event.occurrences} times"}[lang])
    if any(injection_suspected(e.text) for e in event.evidence):
        warnings.append({"tr": "Kayıt metninde talimat benzeri içerik var (olası prompt injection); veri olarak ele alındı",
                         "de": "Ereignistext enthält anweisungsartige Inhalte (mögliche Prompt-Injection); nur als Daten behandelt",
                         "en": "Event text contains instruction-like content (possible prompt injection); treated as data only"}[lang])
    return Diagnosis(event_id=event.event_id, produced_by="rules", summary=f"{event.title}. {_RULE_NOTE[lang]}",
                     hypotheses=hypotheses[:10], missing_information=missing, recommendations=recs, is_definitive=False,
                     warnings=warnings)
