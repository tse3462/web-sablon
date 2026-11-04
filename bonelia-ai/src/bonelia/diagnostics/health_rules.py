"""Findings from disk health and backup state (deterministic, not decided by the AI).

Pure functions: they turn the data from collectors/health.py into DiagnosticEvents,
so they are fully testable without Windows. No repair is ever attached: a failing
disk or a missing backup needs a person, not an automatic action.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from ..contracts import AppIdentity, Confidence, DiagnosticEvent, ErrorCategory, Evidence, Severity

L = dict[str, str]

WEAR_IMPORTANT = 90      # % of rated SSD endurance used
WEAR_CHECK = 80
TEMP_CHECK = 65          # °C
DEFAULT_MAX_AGE_DAYS = 2
WINDOWS_BACKUP_MAX_DAYS = 8  # Windows Backup is often weekly

IMPORTANT_RULES = {"disk.health_failing", "disk.uncorrected_errors", "disk.wear_high",
                   "backup.folder_missing", "backup.empty", "backup.stale", "backup.windows_stale", "backup.windows_failing"}
CHECK_RULES = {"disk.wear_warn", "disk.hot", "backup.none"}

REASON: dict[str, L] = {
    "disk": {"tr": "Disk sağlığı bozuluyor; veri kaybı riski", "de": "Datenträgerzustand verschlechtert sich; Datenverlustrisiko",
             "en": "Disk health is degrading; risk of data loss"},
    "disk_check": {"tr": "Disk için erken uyarı", "de": "Frühwarnung für den Datenträger", "en": "Early warning for the disk"},
    "backup": {"tr": "Yedek güncel değil; veri kaybında geri dönüş yok", "de": "Sicherung nicht aktuell; kein Zurück bei Datenverlust",
               "en": "Backup is not current; no way back after data loss"},
    "backup_none": {"tr": "Yedek tanımlı değil", "de": "Keine Sicherung eingerichtet", "en": "No backup configured"},
}

_T: dict[str, L] = {
    "health": {"tr": "Disk arızalanmak üzere: {n} ({h})", "de": "Datenträger fällt bald aus: {n} ({h})", "en": "Disk is failing: {n} ({h})"},
    "predict": {"tr": "Disk arıza öngörüsü (SMART) bildirildi", "de": "SMART meldet drohenden Datenträgerausfall",
                "en": "SMART reports an imminent disk failure"},
    "errors": {"tr": "Diskte düzeltilemeyen okuma/yazma hataları: {n}", "de": "Nicht korrigierbare Lese-/Schreibfehler: {n}",
               "en": "Uncorrectable read/write errors on disk: {n}"},
    "wear": {"tr": "SSD ömrünün %{w}'i kullanıldı: {n}", "de": "SSD-Lebensdauer zu {w}% verbraucht: {n}", "en": "SSD {w}% worn out: {n}"},
    "hot": {"tr": "Disk çok sıcak ({t} °C): {n}", "de": "Datenträger sehr heiß ({t} °C): {n}", "en": "Disk very hot ({t} °C): {n}"},
    "missing": {"tr": "Yedek klasörü bulunamadı: {p} — harici disk takılı mı?", "de": "Sicherungsordner nicht gefunden: {p} — externe Platte angeschlossen?",
                "en": "Backup folder not found: {p} — is the external drive connected?"},
    "empty": {"tr": "Yedek klasöründe hiç dosya yok: {p}", "de": "Sicherungsordner ist leer: {p}", "en": "Backup folder is empty: {p}"},
    "stale": {"tr": "Yedek eski: {p} — son yedek {d} gün önce (sınır {m} gün)", "de": "Sicherung veraltet: {p} — letzte vor {d} Tagen (Grenze {m})",
              "en": "Backup is old: {p} — last one {d} days ago (limit {m})"},
    "win_stale": {"tr": "Windows yedeği {d} gündür alınmadı", "de": "Windows-Sicherung seit {d} Tagen nicht gelaufen",
                  "en": "Windows Backup has not run for {d} days"},
    "win_failing": {"tr": "Windows yedeği çalışıyor ama hiç başarılı olmadı", "de": "Windows-Sicherung läuft, war aber nie erfolgreich",
                    "en": "Windows Backup runs but never succeeded"},
    "none": {"tr": "Bu bilgisayarda yedek tanımlı değil", "de": "Auf diesem PC ist keine Sicherung eingerichtet",
             "en": "No backup is configured on this PC"},
}

# rule -> (cause, confidence, actions)
ADVICE: dict[str, tuple[L, Confidence, list[L]]] = {
    "disk.health_failing": (
        {"tr": "Disk donanımı bozulmaya başladı; aniden tamamen durabilir", "de": "Die Hardware des Datenträgers versagt; Totalausfall möglich",
         "en": "The disk hardware is failing; it may stop completely without warning"}, Confidence.high,
        [{"tr": "Önemli verilerin yedeğini HEMEN alın", "de": "SOFORT die wichtigen Daten sichern", "en": "Back up important data NOW"},
         {"tr": "Diski en kısa sürede yenisiyle değiştirin", "de": "Datenträger zeitnah ersetzen", "en": "Replace the disk as soon as possible"}]),
    "disk.uncorrected_errors": (
        {"tr": "Disk bazı verileri okuyamıyor/yazamıyor; bozulma başlamış olabilir", "de": "Datenträger kann Daten nicht lesen/schreiben; Defekt möglich",
         "en": "The disk cannot read/write some data; it may be starting to fail"}, Confidence.medium,
        [{"tr": "Yedeğin güncel olduğundan emin olun", "de": "Sicherstellen, dass die Sicherung aktuell ist", "en": "Make sure the backup is current"},
         {"tr": "Diski yetkili kişiye kontrol ettirin, gerekirse değiştirin", "de": "Datenträger prüfen und ggf. tauschen lassen",
          "en": "Have the disk checked and replaced if needed"}]),
    "disk.wear_high": (
        {"tr": "SSD'nin yazma ömrü bitmek üzere", "de": "Die Schreiblebensdauer der SSD ist fast erschöpft", "en": "The SSD's write endurance is almost used up"},
        Confidence.high,
        [{"tr": "Yeni bir SSD planlayın ve verileri taşıyın", "de": "Neue SSD einplanen und Daten umziehen", "en": "Plan a new SSD and migrate the data"}]),
    "disk.wear_warn": (
        {"tr": "SSD ömrünün büyük kısmı kullanıldı", "de": "Großteil der SSD-Lebensdauer verbraucht", "en": "Most of the SSD's lifetime is used"},
        Confidence.medium,
        [{"tr": "Önümüzdeki aylarda disk değişimini planlayın", "de": "Tausch in den nächsten Monaten einplanen", "en": "Plan a replacement in the coming months"}]),
    "disk.hot": (
        {"tr": "Disk aşırı ısınıyor; havalandırma yetersiz olabilir", "de": "Datenträger überhitzt; Belüftung evtl. unzureichend",
         "en": "The disk is overheating; ventilation may be insufficient"}, Confidence.medium,
        [{"tr": "Kasanın havalandırmasını ve fanları kontrol edin", "de": "Gehäusebelüftung und Lüfter prüfen", "en": "Check case ventilation and fans"}]),
    "backup.folder_missing": (
        {"tr": "Yedeklerin yazıldığı disk/klasör erişilemiyor", "de": "Datenträger/Ordner der Sicherung nicht erreichbar",
         "en": "The disk/folder backups are written to is not reachable"}, Confidence.high,
        [{"tr": "Harici diskin takılı ve açık olduğunu kontrol edin", "de": "Prüfen, ob die externe Platte angeschlossen ist",
          "en": "Check the external drive is connected and on"}]),
    "backup.empty": (
        {"tr": "Yedekleme hiç çalışmamış veya yanlış klasör tanımlanmış", "de": "Sicherung lief nie oder falscher Ordner hinterlegt",
         "en": "The backup never ran, or the wrong folder is configured"}, Confidence.medium,
        [{"tr": "Yedek programının ayarlarını ve panelde tanımlı klasörü kontrol edin", "de": "Sicherungsprogramm und hinterlegten Ordner prüfen",
          "en": "Check the backup software and the folder configured in the panel"}]),
    "backup.stale": (
        {"tr": "Yedekleme durmuş; yeni yedek alınmıyor", "de": "Die Sicherung läuft nicht mehr", "en": "Backups have stopped running"}, Confidence.high,
        [{"tr": "Yedek programının çalıştığını ve hedef diskin dolu olmadığını kontrol edin", "de": "Sicherungsprogramm und freien Platz am Ziel prüfen",
          "en": "Check the backup software runs and the target has free space"}]),
    "backup.windows_stale": (
        {"tr": "Windows yedeği planlı olarak çalışmıyor", "de": "Windows-Sicherung läuft nicht planmäßig", "en": "Windows Backup is not running on schedule"},
        Confidence.high,
        [{"tr": "Yedek hedef diskini ve yedekleme zamanlamasını kontrol edin", "de": "Sicherungsziel und Zeitplan prüfen",
          "en": "Check the backup target and schedule"}]),
    "backup.windows_failing": (
        {"tr": "Windows yedeği her seferinde hata veriyor", "de": "Windows-Sicherung schlägt jedes Mal fehl", "en": "Windows Backup fails every time"},
        Confidence.high,
        [{"tr": "Yedek hedefini (disk/ağ) ve yer durumunu kontrol edin", "de": "Sicherungsziel und Speicherplatz prüfen",
          "en": "Check the backup target and its free space"}]),
    "backup.none": (
        {"tr": "Bu bilgisayarda düzenli yedek bulunamadı", "de": "Keine regelmäßige Sicherung gefunden", "en": "No regular backup was found"},
        Confidence.medium,
        [{"tr": "Panelde 'Bilgisayarlar' → 'Yedek' ile yedek klasörünü tanımlayın veya bir yedek kurun",
          "de": "Im Panel unter 'Computer' → 'Sicherung' den Ordner hinterlegen oder eine Sicherung einrichten",
          "en": "Set the backup folder in the panel (Computers → Backup) or set up a backup"}]),
}

_HOST = AppIdentity(app_id="system", name="Windows", adapter_id="generic-windows", recognized=True)


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(p.lower() for p in parts).encode("utf-8")).hexdigest()[:32]


def _num(v: Any) -> float | None:
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _age_days(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return max(0, int((now - t).total_seconds() // 86400))


def disk_health_events(data: dict[str, Any], lang: str = "tr") -> list[DiagnosticEvent]:
    t = lambda k, **kw: _T[k].get(lang, _T[k]["en"]).format(**kw)  # noqa: E731
    out: list[DiagnosticEvent] = []

    def add(rule: str, sev: Severity, title: str, disk: dict[str, Any], key: str) -> None:
        out.append(DiagnosticEvent(
            app=_HOST, category=ErrorCategory.disk, severity=sev, title=title[:300], rule_id=rule,
            fingerprint=_fp("disk-health", rule, key),
            evidence=[Evidence(source="disk_health", kind="metric", code=rule, data={k: disk.get(k) for k in (
                "name", "media", "bus", "health", "operational", "size_gb", "wear", "temperature", "read_errors", "write_errors")})]))

    for d in data.get("disks", []):
        name = str(d.get("name") or "?")[:80]
        health = str(d.get("health") or "")
        if health in ("Warning", "Unhealthy"):
            add("disk.health_failing", Severity.critical if health == "Unhealthy" else Severity.error,
                t("health", n=name, h=health), d, name)
        errs = (_num(d.get("read_errors")) or 0) + (_num(d.get("write_errors")) or 0)
        if errs > 0:
            add("disk.uncorrected_errors", Severity.error, t("errors", n=name), d, name)
        wear = _num(d.get("wear"))
        if wear is not None and wear >= WEAR_IMPORTANT:
            add("disk.wear_high", Severity.error, t("wear", w=int(wear), n=name), d, name)
        elif wear is not None and wear >= WEAR_CHECK:
            add("disk.wear_warn", Severity.warning, t("wear", w=int(wear), n=name), d, name)
        temp = _num(d.get("temperature"))
        if temp is not None and temp >= TEMP_CHECK:
            add("disk.hot", Severity.warning, t("hot", t=int(temp), n=name), d, name)
    if data.get("predict_failure"):
        add("disk.health_failing", Severity.critical, t("predict"), {"name": "SMART"}, "smart-predict")
    return out


def backup_events(policy: dict[str, Any] | None, state: dict[str, Any], lang: str = "tr",
                  now: datetime | None = None) -> list[DiagnosticEvent]:
    t = lambda k, **kw: _T[k].get(lang, _T[k]["en"]).format(**kw)  # noqa: E731
    now = now or datetime.now(timezone.utc)
    policy = policy or {}
    try:
        max_age = max(1, min(int(policy.get("max_age_days") or DEFAULT_MAX_AGE_DAYS), 60))
    except (TypeError, ValueError):
        max_age = DEFAULT_MAX_AGE_DAYS
    out: list[DiagnosticEvent] = []

    def add(rule: str, sev: Severity, title: str, key: str, data: dict[str, Any]) -> None:
        cat = ErrorCategory.configuration if rule == "backup.none" else ErrorCategory.scheduled_job
        out.append(DiagnosticEvent(
            app=_HOST, category=cat, severity=sev, title=title[:300], rule_id=rule, fingerprint=_fp("backup", rule, key),
            evidence=[Evidence(source="backup_check", kind="state", code=rule, data=data)]))

    for f in state.get("folders", []):
        p = str(f.get("path") or "")
        if not f.get("exists"):
            add("backup.folder_missing", Severity.error, t("missing", p=p), p, {"path": p})
        elif not f.get("files"):
            add("backup.empty", Severity.error, t("empty", p=p), p, {"path": p})
        else:
            age = _age_days(f.get("newest"), now)
            if age is not None and age > max_age:
                add("backup.stale", Severity.error, t("stale", p=p, d=age, m=max_age), p,
                    {"path": p, "newest": f.get("newest"), "age_days": age, "max_age_days": max_age})

    win = state.get("windows") or {}
    win_ok = False
    if win.get("last_success"):
        age = _age_days(win["last_success"], now)
        limit = max(max_age, WINDOWS_BACKUP_MAX_DAYS)
        if age is not None and age > limit:
            add("backup.windows_stale", Severity.error, t("win_stale", d=age), "windows",
                {"last_success": win["last_success"], "age_days": age})
        else:
            win_ok = True
    elif win.get("last_event"):
        add("backup.windows_failing", Severity.error, t("win_failing"), "windows", {"last_event": win["last_event"]})
    if not state.get("folders") and not win_ok and not win.get("last_event") and win.get("status") in ("ok", "not_found"):
        add("backup.none", Severity.warning, t("none"), "none", {})
    return out


def advice_for(rule_id: str | None, lang: str = "tr") -> tuple[str, Confidence, list[str]] | None:
    a = ADVICE.get(rule_id or "")
    if not a:
        return None
    cause, conf, actions = a
    return cause.get(lang, cause["en"]), conf, [x.get(lang, x["en"]) for x in actions]


def triage_reason(rule_id: str | None, lang: str = "tr") -> tuple[bool, str] | None:
    """(is_important, reason) for health/backup rules, else None."""
    if rule_id in IMPORTANT_RULES:
        r = REASON["disk" if rule_id.startswith("disk.") else "backup"]
        return True, r.get(lang, r["en"])
    if rule_id in CHECK_RULES:
        r = REASON["backup_none" if rule_id == "backup.none" else "disk_check"]
        return False, r.get(lang, r["en"])
    return None
