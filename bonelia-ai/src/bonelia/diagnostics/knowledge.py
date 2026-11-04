"""Built-in, offline knowledge about well-known Windows error signatures.

Every entry is general technical knowledge (no customer data). Texts exist in
Turkish, German and English. Causes are hypotheses — never definitive diagnoses.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..contracts import Confidence, ErrorCategory, Severity

L = dict[str, str]  # {"tr": ..., "de": ..., "en": ...}


@dataclass(frozen=True)
class KnownSignature:
    rule_id: str
    providers: tuple[str, ...]  # event provider names (case-insensitive)
    event_ids: tuple[int, ...]
    category: ErrorCategory
    severity: Severity
    title: L
    causes: tuple[tuple[L, Confidence], ...]
    actions: tuple[L, ...]
    missing: tuple[L, ...] = field(default_factory=tuple)


def _l(tr: str, de: str, en: str) -> L:
    return {"tr": tr, "de": de, "en": en}


SIGNATURES: tuple[KnownSignature, ...] = (
    KnownSignature(
        "win.app_crash", ("Application Error",), (1000,), ErrorCategory.app_crash, Severity.error,
        _l("Uygulama beklenmedik şekilde kapandı", "Anwendung unerwartet beendet", "Application terminated unexpectedly"),
        (
            (_l("Hatalı modül (DLL) veya uygulama sürümüyle uyumsuz bir eklenti", "Fehlerhaftes Modul (DLL) oder inkompatibles Plug-in",
                "Faulting module (DLL) or an incompatible plug-in"), Confidence.medium),
            (_l("Bozuk kurulum veya eksik güncelleme", "Beschädigte Installation oder fehlendes Update", "Corrupted installation or missing update"),
             Confidence.low),
        ),
        (
            _l("Hatalı modül adını ve istisna kodunu üretici destek kayıtlarıyla karşılaştırın", "Modulnamen und Ausnahmecode mit Herstellerangaben abgleichen",
               "Compare faulting module and exception code with vendor guidance"),
            _l("Uygulamanın en son desteklenen sürümünün kurulu olduğunu doğrulayın", "Prüfen, ob die neueste unterstützte Version installiert ist",
               "Verify the latest supported version is installed"),
        ),
        (_l("Çökme anında kullanıcının yaptığı işlem", "Benutzeraktion zum Absturzzeitpunkt", "User action at time of crash"),),
    ),
    KnownSignature(
        "win.app_hang", ("Application Hang",), (1002,), ErrorCategory.app_hang, Severity.error,
        _l("Uygulama yanıt vermedi ve kapatıldı", "Anwendung reagierte nicht und wurde beendet", "Application stopped responding and was closed"),
        (
            (_l("Uzun süren senkron işlem (ağ, veritabanı veya dosya erişimi)", "Lang laufende synchrone Operation (Netzwerk, DB, Datei)",
                "Long-running synchronous operation (network, database or file)"), Confidence.medium),
            (_l("Kaynak yetersizliği (RAM/CPU)", "Ressourcenmangel (RAM/CPU)", "Resource shortage (RAM/CPU)"), Confidence.low),
        ),
        (_l("Donma anındaki CPU/RAM ve ağ bağlantısını kontrol edin", "CPU/RAM und Netzwerk zum Zeitpunkt prüfen", "Check CPU/RAM and network at that time"),),
    ),
    KnownSignature(
        "win.dotnet_unhandled", (".NET Runtime",), (1026,), ErrorCategory.app_crash, Severity.error,
        _l(".NET uygulamasında işlenmeyen istisna", "Unbehandelte Ausnahme in .NET-Anwendung", "Unhandled exception in .NET application"),
        (
            (_l("Uygulama kodunda yakalanmayan hata (istisna türü kayıtta yazar)", "Nicht abgefangener Fehler im Anwendungscode",
                "Uncaught error in application code (exception type is in the record)"), Confidence.medium),
            (_l("Eksik veya uyumsuz .NET çalışma zamanı", "Fehlende oder inkompatible .NET-Laufzeit", "Missing or incompatible .NET runtime"), Confidence.low),
        ),
        (_l("İstisna türünü ve yığın izini uygulama geliştiricisine iletin", "Ausnahmetyp und Stacktrace an Entwickler weitergeben",
            "Forward the exception type and stack trace to the developer"),),
    ),
    KnownSignature(
        "win.service_crash", ("Service Control Manager",), (7031, 7034, 7023, 7024), ErrorCategory.service_failure, Severity.error,
        _l("Kritik bir Windows hizmeti beklenmedik şekilde durdu", "Windows-Dienst unerwartet beendet", "A Windows service terminated unexpectedly"),
        (
            (_l("Hizmet uygulamasında çökme veya bağımlı hizmet hatası", "Absturz des Dienstes oder Fehler eines abhängigen Dienstes",
                "Service process crash or dependent service failure"), Confidence.medium),
        ),
        (
            _l("Hizmetin kurtarma ayarlarını ve bağımlılıklarını kontrol edin", "Wiederherstellungsoptionen und Abhängigkeiten prüfen",
               "Check the service recovery options and dependencies"),
            _l("Yeniden başlatma yalnızca yönetici onayıyla (Seviye 2)", "Neustart nur mit Admin-Freigabe (Stufe 2)", "Restart only with admin approval (level 2)"),
        ),
    ),
    KnownSignature(
        "win.service_stopped", ("BONELIA:services",), (0,), ErrorCategory.service_failure, Severity.error,
        _l("Otomatik başlaması gereken hizmet durmuş", "Automatisch startender Dienst ist gestoppt",
           "A service set to start automatically is stopped"),
        (
            (_l("Hizmet çöktü veya bağımlı olduğu bir hizmet başlamadı", "Dienst abgestürzt oder abhängiger Dienst nicht gestartet",
                "The service crashed or a service it depends on did not start"), Confidence.medium),
        ),
        (_l("Hizmeti başlatın ve tekrar durup durmadığını izleyin", "Dienst starten und beobachten, ob er erneut stoppt",
            "Start the service and watch whether it stops again"),),
    ),
    KnownSignature(
        "win.service_start_failed", ("Service Control Manager",), (7000, 7009, 7011), ErrorCategory.service_failure, Severity.error,
        _l("Hizmet başlatılamadı veya zaman aşımına uğradı", "Dienst konnte nicht gestartet werden / Zeitüberschreitung",
           "Service failed to start or timed out"),
        (
            (_l("Hatalı hizmet hesabı, eksik dosya veya yavaş bağımlılık", "Falsches Dienstkonto, fehlende Datei oder langsame Abhängigkeit",
                "Wrong service account, missing file or slow dependency"), Confidence.medium),
        ),
        (_l("Hizmet hesabını ve yürütülebilir dosya yolunu doğrulayın", "Dienstkonto und Pfad der ausführbaren Datei prüfen",
            "Verify the service account and executable path"),),
    ),
    KnownSignature(
        "win.unexpected_shutdown", ("Microsoft-Windows-Kernel-Power", "EventLog"), (41, 6008), ErrorCategory.os_stability, Severity.critical,
        _l("Bilgisayar beklenmedik şekilde kapandı", "Computer wurde unerwartet heruntergefahren", "Computer shut down unexpectedly"),
        (
            (_l("Elektrik kesintisi, güç kaynağı veya donanım sorunu", "Stromausfall, Netzteil- oder Hardwareproblem", "Power loss, PSU or hardware issue"),
             Confidence.medium),
            (_l("Sürücü kaynaklı sistem çökmesi (mavi ekran)", "Treiberbedingter Systemabsturz (Bluescreen)", "Driver-related system crash (blue screen)"),
             Confidence.low),
        ),
        (_l("UPS/güç kaynağını ve son sürücü güncellemelerini kontrol edin", "USV/Netzteil und letzte Treiberupdates prüfen",
            "Check UPS/power supply and recent driver updates"),),
    ),
    KnownSignature(
        "win.disk_error", ("disk", "Disk", "Ntfs", "Microsoft-Windows-Ntfs", "storahci", "volmgr"), (7, 11, 51, 55, 98, 153),
        ErrorCategory.disk, Severity.critical,
        _l("Disk veya dosya sistemi hatası", "Datenträger- oder Dateisystemfehler", "Disk or file system error"),
        (
            (_l("Arızalanmaya başlayan disk veya kablo/denetleyici sorunu", "Ausfallender Datenträger oder Kabel-/Controllerproblem",
                "Failing disk or cable/controller problem"), Confidence.medium),
        ),
        (
            _l("Önce yedeğin güncel olduğunu doğrulayın", "Zuerst aktuelle Datensicherung sicherstellen", "First make sure a current backup exists"),
            _l("SMART durumunu kontrol edin; chkdsk yalnızca yönetici onayıyla", "SMART-Status prüfen; chkdsk nur mit Freigabe",
               "Check SMART status; chkdsk only with approval"),
        ),
    ),
    KnownSignature(
        "win.low_memory", ("Microsoft-Windows-Resource-Exhaustion-Detector",), (2004,), ErrorCategory.resource_exhaustion, Severity.warning,
        _l("Sanal bellek yetersiz", "Virtueller Arbeitsspeicher knapp", "Virtual memory low"),
        (
            (_l("Bellek sızıntısı olan bir uygulama veya yetersiz RAM", "Anwendung mit Speicherleck oder zu wenig RAM",
                "An application leaking memory or insufficient RAM"), Confidence.medium),
        ),
        (_l("Kayıtta adı geçen en çok bellek kullanan işlemleri inceleyin", "Im Ereignis genannte Prozesse mit höchstem Verbrauch prüfen",
            "Review the top memory consumers named in the event"),),
    ),
    KnownSignature(
        "win.dns_timeout", ("Microsoft-Windows-DNS-Client",), (1014,), ErrorCategory.connectivity, Severity.warning,
        _l("Ad çözümleme zaman aşımı (DNS)", "Namensauflösung Zeitüberschreitung (DNS)", "Name resolution timed out (DNS)"),
        (
            (_l("DNS sunucusuna ulaşılamıyor veya ağ bağlantısı kararsız", "DNS-Server nicht erreichbar oder Netzwerk instabil",
                "DNS server unreachable or unstable network"), Confidence.medium),
        ),
        (_l("Ağ bağlantısını ve yapılandırılmış DNS sunucularını kontrol edin", "Netzwerk und konfigurierte DNS-Server prüfen",
            "Check network connectivity and configured DNS servers"),),
    ),
    KnownSignature(
        "win.tls_error", ("Schannel",), (36887, 36874, 36888, 36882), ErrorCategory.connectivity, Severity.warning,
        _l("Güvenli bağlantı (TLS) kurulamadı", "Sichere Verbindung (TLS) fehlgeschlagen", "Secure connection (TLS) failed"),
        (
            (_l("Sertifika süresi dolmuş, güvenilmeyen sertifika veya uyumsuz TLS sürümü",
                "Abgelaufenes/nicht vertrauenswürdiges Zertifikat oder inkompatible TLS-Version",
                "Expired/untrusted certificate or incompatible TLS version"), Confidence.medium),
        ),
        (_l("Sunucu sertifikasını ve sistem saatini kontrol edin", "Serverzertifikat und Systemzeit prüfen", "Check server certificate and system clock"),),
    ),
    KnownSignature(
        "db.mssql_login_failed", ("MSSQLSERVER", "MSSQL$SQLEXPRESS"), (18456,), ErrorCategory.database, Severity.error,
        _l("SQL Server oturum açma hatası", "SQL-Server-Anmeldung fehlgeschlagen", "SQL Server login failed"),
        (
            (_l("Yanlış veya süresi dolmuş veritabanı kimlik bilgisi", "Falsche oder abgelaufene DB-Anmeldedaten", "Wrong or expired database credentials"),
             Confidence.medium),
        ),
        (_l("Uygulamanın bağlantı ayarlarını yetkili kişiyle kontrol edin (şifreyi BONELİA AI'ye vermeyin)",
            "Verbindungseinstellungen mit befugter Person prüfen (Passwort nicht an BONELİA AI geben)",
            "Check the app's connection settings with an authorised person (do not give the password to BONELİA AI)"),),
    ),
)

SIGNATURES = SIGNATURES + (
    KnownSignature(
        "db.mssql_log_full", ("MSSQLSERVER", "MSSQL$SQLEXPRESS"), (9002,), ErrorCategory.database, Severity.critical,
        _l("SQL Server işlem günlüğü dolu", "SQL-Server-Transaktionsprotokoll voll", "SQL Server transaction log full"),
        ((_l("Günlük yedeği alınmıyor veya disk dolu; veritabanına yazılamıyor", "Keine Log-Sicherung oder Datenträger voll; DB nicht beschreibbar",
             "No log backups or disk full; the database cannot be written"), Confidence.medium),),
        (_l("Disk alanını ve SQL yedekleme planını yetkili kişiyle kontrol edin", "Speicherplatz und SQL-Sicherungsplan prüfen",
            "Check disk space and the SQL backup plan with an authorised person"),),
    ),
    KnownSignature(
        "db.mssql_io_error", ("MSSQLSERVER", "MSSQL$SQLEXPRESS"), (823, 824, 825), ErrorCategory.database, Severity.critical,
        _l("SQL Server disk okuma/yazma hatası (veri bozulma riski)", "SQL-Server-E/A-Fehler (Gefahr von Datenbeschädigung)",
           "SQL Server I/O error (risk of data corruption)"),
        ((_l("Disk veya depolama denetleyicisi arızası", "Datenträger- oder Controllerfehler", "Disk or storage controller failure"),
          Confidence.medium),),
        (_l("Hemen yedeğin sağlam olduğunu doğrulayın; DBCC CHECKDB yalnızca yetkili kişi", "Sofort Sicherung prüfen; DBCC CHECKDB nur durch Befugte",
            "Verify backups immediately; DBCC CHECKDB only by an authorised person"),),
    ),
    KnownSignature(
        "win.hardware_error", ("Microsoft-Windows-WHEA-Logger",), (1, 17, 18, 19, 46, 47), ErrorCategory.os_stability, Severity.critical,
        _l("Donanım hatası bildirildi (işlemci, bellek veya PCIe)", "Hardwarefehler gemeldet (CPU, RAM oder PCIe)",
           "Hardware error reported (CPU, memory or PCIe)"),
        ((_l("Arızalanan donanım, aşırı ısınma veya güncel olmayan BIOS/sürücü", "Defekte Hardware, Überhitzung oder veraltetes BIOS/Treiber",
             "Failing hardware, overheating or outdated BIOS/driver"), Confidence.medium),),
        (_l("Tekrarlıyorsa donanımı servis için planlayın; BIOS ve yonga seti sürücülerini güncelleyin",
            "Bei Wiederholung Hardwareservice planen; BIOS/Chipsatztreiber aktualisieren",
            "If it repeats, plan hardware service; update BIOS and chipset drivers"),),
    ),
    KnownSignature(
        "win.bugcheck", ("Microsoft-Windows-WER-SystemErrorReporting", "BugCheck"), (1001,), ErrorCategory.os_stability, Severity.critical,
        _l("Bilgisayar mavi ekranla çöktü", "Computer ist mit Bluescreen abgestürzt", "The computer crashed with a blue screen"),
        ((_l("Sürücü veya donanım sorunu", "Treiber- oder Hardwareproblem", "Driver or hardware problem"), Confidence.medium),),
        (_l("Hata kodunu ve son yüklenen sürücüleri kontrol edin", "Stoppcode und zuletzt installierte Treiber prüfen",
            "Check the stop code and recently installed drivers"),),
    ),
    KnownSignature(
        "win.dependency_failed", ("Service Control Manager",), (7001, 7003), ErrorCategory.service_failure, Severity.error,
        _l("Bir hizmet, bağlı olduğu hizmet başlamadığı için başlayamadı", "Dienst startete nicht, weil ein abhängiger Dienst fehlte",
           "A service did not start because a service it depends on failed"),
        ((_l("Bağımlı hizmet durmuş veya devre dışı", "Abhängiger Dienst gestoppt oder deaktiviert", "The dependency is stopped or disabled"),
          Confidence.medium),),
        (_l("Bağımlı hizmetin durumunu kontrol edin", "Status des abhängigen Dienstes prüfen", "Check the dependency's status"),),
    ),
    KnownSignature(
        "win.shadow_copies_deleted", ("volsnap",), (25, 33, 35, 36), ErrorCategory.disk, Severity.error,
        _l("Gölge kopyalar (geri yükleme noktaları) silindi", "Schattenkopien (Wiederherstellungspunkte) gelöscht",
           "Shadow copies (restore points) were deleted"),
        ((_l("Gölge kopya alanı yetersiz veya disk dolu", "Zu wenig Schattenkopie-Speicher oder Datenträger voll",
             "Not enough shadow copy storage or disk full"), Confidence.medium),),
        (_l("Disk alanını ve gölge kopya ayarlarını kontrol edin", "Speicherplatz und VSS-Einstellungen prüfen",
            "Check disk space and shadow copy settings"),),
    ),
)

EXCEPTION_CODES: dict[str, L] = {
    "0xc0000005": _l("Bellek erişim ihlali", "Speicherzugriffsverletzung", "Access violation"),
    "0xc0000409": _l("Yığın arabelleği taşması / güvenlik denetimi", "Stapelpufferüberlauf / Sicherheitsprüfung", "Stack buffer overrun / fail-fast"),
    "0xc00000fd": _l("Yığın taşması (sonsuz özyineleme olabilir)", "Stapelüberlauf (evtl. Endlosrekursion)", "Stack overflow (possible infinite recursion)"),
    "0xc0000374": _l("Yığın (heap) bozulması", "Heap-Beschädigung", "Heap corruption"),
    "0xe0434352": _l("İşlenmeyen .NET istisnası", "Unbehandelte .NET-Ausnahme", "Unhandled .NET exception"),
    "0x80000003": _l("Kesme noktası / assert hatası", "Haltepunkt / Assert-Fehler", "Breakpoint / assertion"),
    "0xc0000142": _l("DLL başlatma hatası", "DLL-Initialisierung fehlgeschlagen", "DLL initialisation failed"),
}


def find_signature(provider: str, event_id: int) -> KnownSignature | None:
    p = (provider or "").lower()
    for sig in SIGNATURES:
        if event_id in sig.event_ids and any(p == x.lower() for x in sig.providers):
            return sig
    return None
