"""Technical service reports (Master prompt §25): JSON, plain text, printable HTML.

A report never claims an intervention that did not happen: `interventions` lists
only gateway results that were actually returned in this session.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from .. import PRODUCT_NAME, __version__
from ..contracts import Diagnosis, ScanResult, utcnow
from ..security.crypto import DataKey

L = {
    "tr": {"title": "Teknik Servis Raporu", "customer": "Müşteri referansı", "computer": "Bilgisayar referansı", "time": "İşlem zamanı",
           "mode": "Tarama türü", "checks": "Yapılan kontroller", "findings": "Tespit edilen hatalar", "evidence": "Kanıt",
           "cause": "Muhtemel neden", "rec": "Önerilen çözüm", "intervention": "Uygulanan müdahale", "none": "Müdahale yapılmadı (salt okunur)",
           "risks": "Kalan riskler", "next": "Sonraki adımlar", "ai": "Analiz kaynağı", "not_definitive": "Bu teşhis kesin değildir; olası nedenleri gösterir.",
           "no_findings": "İncelenen kaynaklarda hata bulunmadı.", "program": "Program", "count": "Tekrar", "notices": "Bildirimler",
           "next_default": ["Önerilen manuel kontrolleri yetkili kişiyle yapın", "Sorun sürerse uygulama üreticisinin desteğine rapor JSON'unu iletin"],
           "risk_default": "Kanıtlar sınırlı olabilir; uygulamaların iç verileri incelenmedi."},
    "de": {"title": "Technischer Servicebericht", "customer": "Kundenreferenz", "computer": "Computerreferenz", "time": "Zeitpunkt",
           "mode": "Scan-Art", "checks": "Durchgeführte Prüfungen", "findings": "Festgestellte Fehler", "evidence": "Nachweis",
           "cause": "Wahrscheinliche Ursache", "rec": "Empfohlene Lösung", "intervention": "Durchgeführter Eingriff",
           "none": "Kein Eingriff (nur lesend)", "risks": "Verbleibende Risiken", "next": "Nächste Schritte", "ai": "Analysequelle",
           "not_definitive": "Diese Diagnose ist nicht gesichert; sie zeigt mögliche Ursachen.", "no_findings": "Keine Fehler in den geprüften Quellen.",
           "program": "Programm", "count": "Anzahl", "notices": "Hinweise",
           "next_default": ["Empfohlene manuelle Prüfungen mit befugter Person durchführen", "Bei Fortbestehen Bericht-JSON an Herstellersupport senden"],
           "risk_default": "Nachweise können begrenzt sein; interne Anwendungsdaten wurden nicht geprüft."},
    "en": {"title": "Technical Service Report", "customer": "Customer reference", "computer": "Computer reference", "time": "Time",
           "mode": "Scan type", "checks": "Checks performed", "findings": "Detected errors", "evidence": "Evidence",
           "cause": "Likely cause", "rec": "Recommended solution", "intervention": "Intervention applied", "none": "No intervention (read-only)",
           "risks": "Remaining risks", "next": "Next steps", "ai": "Analysis source", "not_definitive": "This diagnosis is not definitive; it lists possible causes.",
           "no_findings": "No errors found in the inspected sources.", "program": "Program", "count": "Count", "notices": "Notices",
           "next_default": ["Perform the recommended manual checks with an authorised person", "If the issue persists, send the report JSON to the vendor"],
           "risk_default": "Evidence may be limited; internal application data was not inspected."},
}


def build_report(scan: ScanResult, tenant_ref: str | None, lang: str = "tr", diagnoses: list[Diagnosis] | None = None,
                 ai_mode: str = "rules", notices: list[str] | None = None,
                 interventions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    diags = {d.event_id: d for d in (diagnoses or scan.diagnoses)}
    findings = []
    for ev in scan.events:
        d = diags.get(ev.event_id)
        findings.append({
            "event_id": ev.event_id, "program": ev.app.name, "program_version": ev.app.version, "category": ev.category.value,
            "severity": ev.severity.value, "title": ev.title, "occurrences": ev.occurrences, "occurred_at": ev.occurred_at.isoformat(),
            "evidence": [{"source": e.source, "code": e.code, "text": e.text[:600], "data": e.data} for e in ev.evidence[:3]],
            "likely_causes": [{"cause": h.cause, "confidence": h.confidence.value} for h in (d.hypotheses if d else [])],
            "missing_information": d.missing_information if d else [],
            "recommendations": [r.description for r in (d.recommendations if d else [])],
            "analysis_source": d.produced_by if d else "none", "warnings": d.warnings if d else [],
            "triage": ev.triage.value, "triage_reason": ev.triage_reason,
            "repair_tool": ev.repair_tool, "repair_params": ev.repair_params,
            "definitive": False,
        })
    return {
        "product": PRODUCT_NAME, "version": __version__, "report_type": "technical_service_report", "language": lang,
        "generated_at": utcnow().isoformat(), "scan_id": scan.scan_id, "scan_mode": scan.mode,
        "customer_ref": tenant_ref or "unregistered", "computer_ref": scan.system.hostname_ref if scan.system else None,
        "system": scan.system.model_dump(mode="json") if scan.system else None,
        "checks_performed": scan.collector_status, "findings": findings, "ai_mode": ai_mode, "notices": notices or [],
        "interventions": interventions or [],
        "remaining_risks": [L[lang]["risk_default"]], "next_steps": L[lang]["next_default"],
    }


def render_text(rep: dict[str, Any]) -> str:
    t = L[rep.get("language", "tr")]
    out = [f"{rep['product']} — {t['title']}", "=" * 60,
           f"{t['customer']}: {rep['customer_ref']}", f"{t['computer']}: {rep['computer_ref']}",
           f"{t['time']}: {rep['generated_at']}", f"{t['mode']}: {rep['scan_mode']}", f"{t['ai']}: {rep['ai_mode']}", "",
           f"{t['checks']}:"]
    out += [f"  - {k}: {v}" for k, v in rep["checks_performed"].items()]
    if rep["notices"]:
        out += ["", f"{t['notices']}:"] + [f"  ! {n}" for n in rep["notices"]]
    out += ["", f"{t['findings']}:"]
    if not rep["findings"]:
        out.append(f"  {t['no_findings']}")
    for i, f in enumerate(rep["findings"], 1):
        tri = {"important": "!!", "check": "?", "harmless": "-"}.get(f.get("triage", "check"), "?")
        out += [f"", f"[{i}] {tri} ({f['severity'].upper()}) {f['title']}  — {f.get('triage_reason', '')}", f"    {t['program']}: {f['program']} {f['program_version'] or ''}  "
                f"{t['count']}: {f['occurrences']}"]
        for e in f["evidence"][:1]:
            out.append(f"    {t['evidence']}: {e['source']} {e['code'] or ''} — {e['text'][:200]}")
        for c in f["likely_causes"][:3]:
            out.append(f"    {t['cause']} [{c['confidence']}]: {c['cause']}")
        for r in f["recommendations"][:3]:
            out.append(f"    {t['rec']}: {r}")
        for w in f["warnings"]:
            out.append(f"    ! {w}")
    out += ["", f"{t['intervention']}:"]
    out += [f"  - {i['tool_id']}: {i['outcome']}" for i in rep["interventions"]] or [f"  {t['none']}"]
    out += ["", f"{t['risks']}:"] + [f"  - {r}" for r in rep["remaining_risks"]]
    out += ["", f"{t['next']}:"] + [f"  - {s}" for s in rep["next_steps"]]
    out += ["", t["not_definitive"]]
    return "\n".join(out)


def render_html(rep: dict[str, Any]) -> str:
    """Printable HTML (use the browser's 'Print to PDF' for a PDF copy in v0.1)."""
    e = html.escape
    t = L[rep.get("language", "tr")]
    rows = []
    for f in rep["findings"]:
        causes = "".join(f"<li><b>{e(c['confidence'])}</b> — {e(c['cause'])}</li>" for c in f["likely_causes"][:4])
        recs = "".join(f"<li>{e(r)}</li>" for r in f["recommendations"][:4])
        ev = "".join(f"<div class=ev><code>{e(x['source'])} {e(x['code'] or '')}</code> {e(x['text'][:300])}</div>" for x in f["evidence"][:2])
        warn = "".join(f"<div class=warn>⚠ {e(w)}</div>" for w in f["warnings"])
        tri = {"important": "!!", "check": "?", "harmless": "–"}.get(f.get("triage", "check"), "?")
        rows.append(f"<section class='f {e(f['severity'])}'><h3>{e(tri)} {e(f['title'])}</h3><p><i>{e(f.get('triage_reason', ''))}</i></p><p>{e(t['program'])}: {e(f['program'])} "
                    f"{e(f['program_version'] or '')} · {e(t['count'])}: {f['occurrences']} · {e(f['analysis_source'])}</p>{ev}"
                    f"<h4>{e(t['cause'])}</h4><ul>{causes}</ul><h4>{e(t['rec'])}</h4><ul>{recs}</ul>{warn}</section>")
    checks = "".join(f"<li><code>{e(k)}</code>: {e(str(v))}</li>" for k, v in rep["checks_performed"].items())
    inter = "".join(f"<li>{e(i['tool_id'])}: {e(i['outcome'])}</li>" for i in rep["interventions"]) or f"<li>{e(t['none'])}</li>"
    notices = "".join(f"<div class=warn>{e(n)}</div>" for n in rep["notices"])
    return f"""<!doctype html><html lang="{e(rep.get('language','tr'))}"><head><meta charset="utf-8">
<title>{e(rep['product'])} — {e(t['title'])}</title><style>
body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:24px;color:#14202b;background:#fff}}h1{{font-size:20px}}
.meta td{{padding:2px 12px 2px 0}} .f{{border:1px solid #d5dde5;border-left:5px solid #888;border-radius:6px;padding:10px 14px;margin:12px 0}}
.f.critical{{border-left-color:#b00020}}.f.error{{border-left-color:#d9480f}}.f.warning{{border-left-color:#e6a700}}
.ev{{font-size:12px;color:#445;background:#f4f6f8;padding:4px 8px;border-radius:4px;margin:4px 0;word-break:break-word}}
.warn{{color:#8a5300;font-size:13px}} h4{{margin:8px 0 2px;font-size:13px}} footer{{margin-top:24px;font-size:12px;color:#556}}
</style></head><body><h1>{e(rep['product'])} — {e(t['title'])}</h1>
<table class=meta><tr><td>{e(t['customer'])}</td><td>{e(str(rep['customer_ref']))}</td></tr>
<tr><td>{e(t['computer'])}</td><td>{e(str(rep['computer_ref']))}</td></tr><tr><td>{e(t['time'])}</td><td>{e(rep['generated_at'])}</td></tr>
<tr><td>{e(t['mode'])}</td><td>{e(rep['scan_mode'])}</td></tr><tr><td>{e(t['ai'])}</td><td>{e(rep['ai_mode'])}</td></tr></table>
{notices}<h2>{e(t['findings'])}</h2>{''.join(rows) or '<p>' + e(t['no_findings']) + '</p>'}
<h2>{e(t['checks'])}</h2><ul>{checks}</ul><h2>{e(t['intervention'])}</h2><ul>{inter}</ul>
<h2>{e(t['risks'])}</h2><ul>{''.join(f'<li>{e(r)}</li>' for r in rep['remaining_risks'])}</ul>
<h2>{e(t['next'])}</h2><ul>{''.join(f'<li>{e(s)}</li>' for s in rep['next_steps'])}</ul>
<footer>{e(t['not_definitive'])} · {e(rep['product'])} {e(rep['version'])}</footer></body></html>"""


def save_encrypted(rep: dict[str, Any], reports_dir: Path, key: DataKey) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{rep['scan_id']}.bnr"
    path.write_bytes(key.encrypt(json.dumps(rep, ensure_ascii=False).encode("utf-8"), aad=b"bonelia-report"))
    return path


def load_encrypted(path: Path, key: DataKey) -> dict[str, Any]:
    return json.loads(key.decrypt(path.read_bytes(), aad=b"bonelia-report").decode("utf-8"))


def export(rep: dict[str, Any], dest_dir: Path, formats: tuple[str, ...] = ("json", "txt", "html")) -> list[Path]:
    """Write a plaintext copy OUTSIDE the USB (operator's explicit choice)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for fmt in formats:
        p = dest_dir / f"BONELIA-AI-report-{rep['scan_id']}.{fmt}"
        if fmt == "json":
            p.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "txt":
            p.write_text(render_text(rep), encoding="utf-8")
        elif fmt == "html":
            p.write_text(render_html(rep), encoding="utf-8")
        else:
            continue
        out.append(p)
    return out
