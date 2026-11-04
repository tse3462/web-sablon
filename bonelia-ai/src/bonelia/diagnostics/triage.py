"""Deterministic triage: important / check / harmless (not decided by the AI).

The harmless list contains well-known, routine Windows log entries that appear on
almost every PC and do not need action unless a specific symptom exists. Several
entries come from the owner's first real scan (German Windows 11, 2026-11-04).
"""

from __future__ import annotations

from ..contracts import DiagnosticEvent, ErrorCategory, Severity, Triage
from .health_rules import triage_reason as _health_reason

L = dict[str, str]

# (provider lower-case, event id) -> reason
HARMLESS: dict[tuple[str, int], L] = {
    ("win32k", 700): {"tr": "Güç yönetiminin olağan giriş bildirimi", "de": "Normale Meldung der Energieverwaltung",
                      "en": "Routine power-management input notice"},
    ("win32k", 701): {"tr": "Güç yönetiminin olağan giriş bildirimi", "de": "Normale Meldung der Energieverwaltung",
                      "en": "Routine power-management input notice"},
    (".net runtime", 1000): {"tr": ".NET telemetri bildirimi; uygulama hatası değil", "de": ".NET-Telemetriemeldung; kein Anwendungsfehler",
                             "en": ".NET telemetry notice; not an application error"},
    ("microsoft office 16", 2011): {"tr": "Office lisans kontrolü bildirimi; Office çalışıyorsa önemsiz",
                                    "de": "Office-Lizenzprüfung; unkritisch, solange Office funktioniert",
                                    "en": "Office licensing check; harmless while Office works"},
    ("microsoft-windows-deviceassociationservice", 3501): {"tr": "Bir cihaz eşleştirme denemesi başarısız; sorun yoksa önemsiz",
                                                           "de": "Fehlgeschlagener Gerätekopplungsversuch; unkritisch ohne Symptome",
                                                           "en": "A device pairing attempt failed; harmless without symptoms"},
    ("bthmini", 16): {"tr": "Bluetooth eşleştirme kimlik doğrulaması başarısız; cihaz çalışıyorsa önemsiz",
                      "de": "Bluetooth-Kopplung fehlgeschlagen; unkritisch, wenn das Gerät funktioniert",
                      "en": "Bluetooth pairing authentication failed; harmless if the device works"},
    ("microsoft-windows-windowsupdateclient", 20): {"tr": "Bir güncelleme yüklenemedi; Windows otomatik olarak yeniden dener",
                                                    "de": "Ein Update schlug fehl; Windows versucht es automatisch erneut",
                                                    "en": "An update failed; Windows retries automatically"},
    ("microsoft-windows-kernel-processor-power", 37): {"tr": "İşlemci güç/ısı nedeniyle yavaşlatıldı; bilgisayar yavaş değilse normal",
                                                      "de": "CPU wurde aus Energie-/Temperaturgründen gedrosselt; normal, wenn der PC nicht langsam ist",
                                                      "en": "CPU throttled for power/thermal reasons; normal unless the PC is slow"},
    ("microsoft-windows-distributedcom", 10016): {"tr": "Bilinen, zararsız Windows izin bildirimi", "de": "Bekannte, harmlose Windows-Berechtigungsmeldung",
                                                  "en": "Known, harmless Windows permission notice"},
    ("microsoft-windows-distributedcom", 10010): {"tr": "Bir COM sunucusu zamanında kaydolmadı; tekrar etmiyorsa önemsiz",
                                                  "de": "COM-Server meldete sich nicht rechtzeitig; unkritisch, wenn einmalig",
                                                  "en": "A COM server did not register in time; harmless if isolated"},
    ("perflib", 1008): {"tr": "Performans sayacı yüklenemedi; olağan", "de": "Leistungsindikator nicht geladen; üblich",
                        "en": "Performance counter not loaded; common"},
    ("perflib", 1023): {"tr": "Performans sayacı yüklenemedi; olağan", "de": "Leistungsindikator nicht geladen; üblich",
                        "en": "Performance counter not loaded; common"},
    ("microsoft-windows-security-spp", 8198): {"tr": "Lisans etkinleştirme denemesi; olağan", "de": "Lizenzaktivierungsversuch; üblich",
                                               "en": "Licence activation attempt; common"},
    ("microsoft-windows-time-service", 129): {"tr": "Saat eşitleme geçici olarak başarısız; olağan", "de": "Zeitsynchronisierung kurz fehlgeschlagen; üblich",
                                              "en": "Time sync temporarily failed; common"},
}

CHECK: dict[tuple[str, int], L] = {
    ("vss", 12292): {"tr": "Gölge kopya (yedekleme / geri yükleme) etkilenebilir; yedeklerin çalıştığını kontrol edin",
                     "de": "Schattenkopien (Sicherung/Wiederherstellung) können betroffen sein; Sicherungen prüfen",
                     "en": "Shadow copies (backup/restore) may be affected; verify backups work"},
    ("vss", 22): {"tr": "Gölge kopya (yedekleme / geri yükleme) etkilenebilir; yedeklerin çalıştığını kontrol edin",
                  "de": "Schattenkopien (Sicherung/Wiederherstellung) können betroffen sein; Sicherungen prüfen",
                  "en": "Shadow copies (backup/restore) may be affected; verify backups work"},
    ("vss", 8193): {"tr": "Gölge kopya hizmeti hatası; yedekleri kontrol edin", "de": "VSS-Fehler; Sicherungen prüfen",
                    "en": "Shadow copy service error; check backups"},
}

_TXT = {
    "important_sig": {"tr": "Ciddi sorun işareti", "de": "Hinweis auf ein ernstes Problem", "en": "Sign of a serious problem"},
    "repeat_crash": {"tr": "Program tekrar tekrar çöküyor", "de": "Programm stürzt wiederholt ab", "en": "Program crashes repeatedly"},
    "single_crash": {"tr": "Tek seferlik çökme; tekrar ederse önemli", "de": "Einmaliger Absturz; wichtig, falls er sich wiederholt",
                     "en": "One-off crash; important if it repeats"},
    "service_stopped": {"tr": "Otomatik çalışması gereken hizmet durmuş", "de": "Automatisch startender Dienst ist gestoppt",
                        "en": "A service that should run automatically is stopped"},
    "critical": {"tr": "Kritik önem derecesi", "de": "Kritischer Schweregrad", "en": "Critical severity"},
    "error_unknown": {"tr": "Bilinmeyen hata; incelemeye değer", "de": "Unbekannter Fehler; prüfenswert", "en": "Unknown error; worth a look"},
    "warn_repeat": {"tr": "Sık tekrarlanan uyarı", "de": "Häufig wiederholte Warnung", "en": "Frequently repeated warning"},
    "warn_single": {"tr": "Tek tük uyarı; belirti yoksa önemsiz", "de": "Vereinzelte Warnung; ohne Symptome unkritisch",
                    "en": "Occasional warning; harmless without symptoms"},
    "disk_full": {"tr": "Disk dolmak üzere", "de": "Datenträger fast voll", "en": "Disk almost full"},
    "test": {"tr": "Kontrollü test kaydı", "de": "Kontrollierter Testeintrag", "en": "Controlled test entry"},
}

IMPORTANT_RULES = {"win.unexpected_shutdown", "win.disk_error", "win.service_crash", "db.mssql_login_failed", "win.service_stopped",
                   "db.mssql_log_full", "db.mssql_io_error", "win.hardware_error", "win.bugcheck"}


def _provider_and_id(event: DiagnosticEvent) -> tuple[str, int] | None:
    for ev in event.evidence:
        if ev.source.startswith("windows_event_log:") and ev.code and "/" in ev.code:
            prov, _, eid = ev.code.rpartition("/")
            if eid.isdigit():
                return prov.lower(), int(eid)
    return None


def classify(event: DiagnosticEvent, lang: str = "tr") -> tuple[Triage, str]:
    t = lambda k: _TXT[k].get(lang, _TXT[k]["en"])  # noqa: E731
    key = _provider_and_id(event)
    if key and key[0].startswith("bonelia"):
        return Triage.check, t("test")
    if key in HARMLESS:
        return Triage.harmless, HARMLESS[key].get(lang, HARMLESS[key]["en"])
    if key in CHECK:
        return Triage.check, CHECK[key].get(lang, CHECK[key]["en"])
    health = _health_reason(event.rule_id, lang)  # disk health / backup findings
    if health is not None:
        return (Triage.important if health[0] else Triage.check), health[1]
    if event.rule_id in IMPORTANT_RULES:
        return Triage.important, t("service_stopped") if event.rule_id == "win.service_stopped" else t("important_sig")
    if event.rule_id in ("win.app_crash", "win.app_hang", "win.dotnet_unhandled"):
        return (Triage.important, t("repeat_crash")) if event.occurrences >= 3 else (Triage.check, t("single_crash"))
    if event.rule_id == "metric.disk_full":
        return (Triage.important if event.severity == Severity.critical else Triage.check), t("disk_full")
    if event.severity == Severity.critical:
        return Triage.important, t("critical")
    if event.severity == Severity.error or event.category != ErrorCategory.unknown:
        return Triage.check, t("error_unknown")
    if event.occurrences >= 5:
        return Triage.check, t("warn_repeat")
    return Triage.harmless, t("warn_single")


def apply_triage(events: list[DiagnosticEvent], lang: str = "tr") -> list[DiagnosticEvent]:
    for ev in events:
        ev.triage, ev.triage_reason = classify(ev, lang)
    order = {Triage.important: 0, Triage.check: 1, Triage.harmless: 2}
    return sorted(events, key=lambda e: order[e.triage])  # stable: keeps severity/occurrence order within a group
