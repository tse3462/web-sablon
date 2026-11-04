"""Shared session logic for the CLI and the local UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..contracts import ScanResult
from ..security.crypto import DataKey, DeviceCredentials, Vault
from . import reports
from .client import FakeServerError, ServerClient, ServerError, ServerTimeout, ServerUnavailable
from .offline_queue import OfflineQueue
from .portable import PortableHome
from .scan import run_scan

MSG = {
    "offline": {"tr": "Merkezi BONELİA AI Server'a bağlanılamadı — çevrimdışı mod. Olaylar şifreli kuyruğa alındı; yerel kural teşhisi gösteriliyor.",
                "de": "BONELİA AI Server nicht erreichbar — Offline-Modus. Ereignisse verschlüsselt zwischengespeichert; lokale Regeldiagnose.",
                "en": "BONELİA AI Server unreachable — offline mode. Events queued (encrypted); showing local rule diagnosis."},
    "timeout": {"tr": "Sunucu bağlı, ancak yapay zekâ analizi zamanında bitmedi. Yerel kural teşhisi gösteriliyor; daha küçük bir model veya daha az olay deneyin.",
                "de": "Server verbunden, aber die KI-Analyse wurde nicht rechtzeitig fertig. Lokale Regeldiagnose wird angezeigt; kleineres Modell oder weniger Ereignisse versuchen.",
                "en": "Server connected, but the AI analysis did not finish in time. Showing local rule diagnosis; try a smaller model or fewer events."},
    "fake": {"tr": "UYARI: Sunucu imzası doğrulanamadı — sahte sunucu olabilir. Bağlantı kesildi.",
             "de": "WARNUNG: Serversignatur ungültig — möglicher gefälschter Server. Verbindung abgebrochen.",
             "en": "WARNING: server signature invalid — possible fake server. Connection aborted."},
    "not_enrolled": {"tr": "Bu USB henüz kayıtlı değil; yalnızca yerel teşhis yapılabilir.",
                     "de": "Dieser USB-Stick ist nicht registriert; nur lokale Diagnose möglich.",
                     "en": "This USB device is not enrolled; only local diagnostics are available."},
    "revoked": {"tr": "Bu cihazın yetkisi sunucu tarafından iptal edilmiş.", "de": "Die Berechtigung dieses Geräts wurde widerrufen.",
                "en": "This device's access has been revoked by the server."},
}


@dataclass
class Session:
    home: PortableHome
    lang: str = "tr"
    creds: DeviceCredentials | None = None
    client: ServerClient | None = None
    last_scan: ScanResult | None = None
    last_report: dict[str, Any] | None = None
    interventions: list[dict[str, Any]] = field(default_factory=list)
    ca_file: str | None = None

    @property
    def enrolled(self) -> bool:
        return Vault(self.home.vault_path).exists()

    def unlock(self, passphrase: str, transport=None) -> None:
        self.creds = Vault(self.home.vault_path).load(passphrase)
        self.client = ServerClient(self.creds, transport=transport, ca_file=self.ca_file)

    @property
    def data_key(self) -> DataKey | None:
        return DataKey(self.creds.data_key) if self.creds else None

    def server_status(self) -> dict[str, Any]:
        if not self.client:
            return {"connected": False, "reason": "not_unlocked" if self.enrolled else "not_enrolled"}
        try:
            h = self.client.health()
            return {"connected": True, "version": h.get("version"), "ai": h.get("ai")}
        except FakeServerError:
            return {"connected": False, "reason": "fake_server", "message": MSG["fake"][self.lang]}
        except (ServerUnavailable, ServerError) as exc:
            return {"connected": False, "reason": type(exc).__name__}

    def scan(self, mode: str = "quick", app_query: str | None = None, hours: int | None = None,
             log_paths: list[str] | None = None, include_eventlog: bool = True) -> ScanResult:
        settings = self.home.settings()
        self.last_scan = run_scan(mode=mode, salt=self.home.salt(), lang=self.lang, app_query=app_query,
                                  log_paths=log_paths if log_paths is not None else settings.get("log_paths", []), hours=hours,
                                  include_eventlog=include_eventlog)
        self.last_report = reports.build_report(self.last_scan, self.creds.tenant_id if self.creds else None, self.lang)
        self._persist()
        return self.last_scan

    def analyze(self, allow_cloud: bool = False) -> dict[str, Any]:
        """Send the last scan to the server. Falls back to local rules when offline."""
        if self.last_scan is None:
            raise RuntimeError("no scan yet")
        scan = self.last_scan
        notices: list[str] = []
        if not self.client:
            notices.append(MSG["not_enrolled"][self.lang])
            self.last_report = reports.build_report(scan, None, self.lang, notices=notices)
            return self.last_report
        to_send = [e for e in scan.events][:25]
        try:
            if to_send:
                res = self.client.analyze(to_send, scan.system, allow_cloud, self.lang)
                self._drain_queue(max_entries=1)  # catch up on earlier offline events without delaying this result
                diags = res.diagnoses + [d for d in scan.diagnoses if d.event_id not in {x.event_id for x in res.diagnoses}]
                self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, diagnoses=diags,  # type: ignore[union-attr]
                                                        ai_mode=res.ai_mode, notices=res.notices, interventions=self.interventions)
            else:
                self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, interventions=self.interventions)  # type: ignore[union-attr]
        except FakeServerError:
            notices.append(MSG["fake"][self.lang])
            self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, notices=notices)  # type: ignore[union-attr]
        except ServerTimeout:
            notices.append(MSG["timeout"][self.lang])  # server got the events; do not queue duplicates
            self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, ai_mode="rules-timeout", notices=notices)  # type: ignore[union-attr]
        except ServerUnavailable:
            OfflineQueue(self.home.path("queue"), self.data_key).push(to_send)  # type: ignore[arg-type]
            notices.append(MSG["offline"][self.lang])
            self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, ai_mode="rules-offline", notices=notices)  # type: ignore[union-attr]
        except ServerError as exc:
            notices.append(MSG["revoked"][self.lang] if exc.detail == "device_revoked" else f"server: {exc.status} {exc.detail}")
            self.last_report = reports.build_report(scan, self.creds.tenant_id, self.lang, notices=notices)  # type: ignore[union-attr]
        self._persist()
        return self.last_report

    def _drain_queue(self, max_entries: int) -> None:
        if self.client is None or self.data_key is None:
            return
        try:
            OfflineQueue(self.home.path("queue"), self.data_key).drain(
                lambda evs: self.client.analyze(evs, None, False, self.lang), max_entries=max_entries)  # type: ignore[union-attr]
        except Exception:
            pass  # the queue is best effort; the current result is already available

    def _persist(self) -> None:
        """Reports on the USB are stored encrypted only. Without a vault nothing is written."""
        if self.last_report is not None and self.data_key is not None:
            reports.save_encrypted(self.last_report, self.home.path("reports"), self.data_key)

    def export_last(self, dest: Path) -> list[Path]:
        if self.last_report is None:
            raise RuntimeError("no report yet")
        return reports.export(self.last_report, dest)
