"""Universal built-in tool catalogue for v0.1 (application-independent).

The Windows service tools are registered as enabled but still do nothing until the
customer allows repairs once (tenant level, set with `bonelia-server allow-repairs`)
and the device holds the `repair:windows` scope. Application-specific tools come
from optional adapters (namespaced, disabled by default). Level-3 tools do not exist.
"""

from __future__ import annotations

from ..contracts import RiskLevel
from .tools import ParamSpec, ToolRegistry, ToolSpec

SERVICE_NAME = r"[A-Za-z0-9_.-]{1,80}"


def _snapshot_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="generic.collect_snapshot", description="Collect read-only system/app snapshot (client side)",
        platforms=("windows", "any"), risk_level=RiskLevel.READ_ONLY, required_scope="diagnose", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True, rollback="n/a (read-only)", timeout_s=60, max_runs_per_hour=60,
        verification="n/a", side_effects="none", enabled=True)


def _start_service_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.start_service",
        description="Start a stopped Windows service that is configured to start automatically",
        platforms=("windows",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:windows", required_role="operator",
        params={"service_name": ParamSpec(str, pattern=SERVICE_NAME)}, supports_dry_run=True, idempotent=True,
        rollback="Stop the service again (Stop-Service) if the application misbehaves",
        timeout_s=120, max_runs_per_hour=5, verification="Service status == Running after the action",
        side_effects="The service starts as Windows intended; critical system services are refused",
        enabled=True, runs_on="client",
        risk_text={"tr": "Durmuş hizmet başlatılır. Windows yönetici izni (UAC) isteyebilir.",
                   "de": "Der gestoppte Dienst wird gestartet. Windows kann nach Administratorrechten (UAC) fragen.",
                   "en": "The stopped service is started. Windows may ask for administrator rights (UAC)."})


def _restart_service_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.restart_service", description="Restart one named Windows service (not critical system services)",
        platforms=("windows",), risk_level=RiskLevel.ADMIN_APPROVED, required_scope="repair:windows", required_role="operator",
        params={"service_name": ParamSpec(str, pattern=SERVICE_NAME)}, supports_dry_run=True, idempotent=False,
        rollback="Service returns to its previous state on its own; if it fails to start, start it again or restore its configuration",
        timeout_s=150, max_runs_per_hour=2, verification="Service status == Running after the restart",
        side_effects="Brief interruption: users of this service may be disconnected for a few seconds",
        enabled=True, runs_on="client",
        risk_text={"tr": "Hizmet birkaç saniyeliğine durup yeniden başlar. O sırada bu hizmeti kullanan program bağlantısını kaybedebilir.",
                   "de": "Der Dienst stoppt kurz und startet neu. Programme, die ihn nutzen, können kurz die Verbindung verlieren.",
                   "en": "The service stops briefly and starts again. Programs using it may briefly lose their connection."})


def _flush_dns_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.flush_dns", description="Clear the Windows DNS cache (name resolution problems)",
        platforms=("windows",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:windows", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True, rollback="Not needed: the cache refills automatically",
        timeout_s=60, max_runs_per_hour=3, verification="A DNS lookup succeeds after the flush",
        side_effects="None noticeable; the next lookups take a few milliseconds longer", enabled=True, runs_on="client",
        risk_text={"tr": "DNS önbelleği temizlenir; risk yok.", "de": "DNS-Cache wird geleert; kein Risiko.", "en": "DNS cache is cleared; no risk."})


def _clean_temp_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.clean_temp", description="Delete temporary files older than 7 days (system and account temp folders)",
        platforms=("windows",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:windows", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True,
        rollback="Not possible (files are deleted) — limited to temp folders and files older than 7 days, like Windows Disk Cleanup",
        timeout_s=300, max_runs_per_hour=1, verification="No file older than 7 days remains except files in use",
        side_effects="Frees disk space; files in use are skipped", enabled=True, runs_on="client",
        risk_text={"tr": "Geçici klasörlerdeki 7 günden eski dosyalar silinir.", "de": "Temporäre Dateien älter als 7 Tage werden gelöscht.",
                   "en": "Temporary files older than 7 days are deleted."})


# A program file name as Windows shows it in Task Manager (no folder, no command characters).
PROGRAM_NAME = r"[A-Za-z0-9][A-Za-z0-9 _.()+-]{0,75}\.[Ee][Xx][Ee]"


def _restart_hung_app_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.restart_hung_app",
        description="End a program whose window has not answered for minutes and start it again (user request 06.11.2026)",
        platforms=("windows",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:windows", required_role="operator",
        params={"pid": ParamSpec(int, min=1, max=2**32 - 1), "name": ParamSpec(str, pattern=PROGRAM_NAME)},
        supports_dry_run=True, idempotent=True,
        rollback="Not needed: the program is started again; work not saved before it froze is lost (it could not be saved anyway)",
        timeout_s=60, max_runs_per_hour=6, verification="The restarted program is running a few seconds later",
        side_effects="The frozen program closes and opens again; Windows programs and BONELIA itself are refused",
        enabled=True, runs_on="client",
        risk_text={"tr": "Dakikalardır yanıt vermeyen program kapatılıp yeniden açılır.",
                   "de": "Ein seit Minuten hängendes Programm wird beendet und neu gestartet.",
                   "en": "A program that has not responded for minutes is ended and started again."})


def _close_program_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="windows.close_program",
        description="Ask a program to close like a click on its X (never forced) and optionally start it again -- frees memory",
        platforms=("windows",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:windows", required_role="operator",
        params={"pid": ParamSpec(int, min=1, max=2**32 - 1), "name": ParamSpec(str, pattern=PROGRAM_NAME),
                "restart": ParamSpec(bool, required=False)},
        supports_dry_run=True, idempotent=True,
        rollback="Open the program again; a program with unsaved work asks to save and stays open",
        timeout_s=90, max_runs_per_hour=6, verification="The program has ended (and, if asked, runs again)",
        side_effects="The program closes like a click on its X; Windows programs and BONELIA itself are refused",
        enabled=True, runs_on="client",
        risk_text={"tr": "Program, X'e basılmış gibi kapatılır; kaydedilmemiş iş varsa program sorar ve açık kalır.",
                   "de": "Das Programm wird wie mit Klick auf X geschlossen; mit ungespeicherter Arbeit fragt es und bleibt offen.",
                   "en": "The program is closed like a click on its X; with unsaved work it asks and stays open."})


SAFE_AUTO_TOOLS = ("windows.start_service", "windows.flush_dns", "windows.clean_temp", "windows.restart_hung_app",
                   "windows.close_program")


def default_registry(enable: set[str] | None = None) -> ToolRegistry:
    reg = ToolRegistry()
    for spec in (_snapshot_tool(), _start_service_tool(), _restart_service_tool(), _flush_dns_tool(), _clean_temp_tool(),
                 _restart_hung_app_tool(), _close_program_tool()):
        if enable and spec.tool_id in enable and spec.risk_level < RiskLevel.CRITICAL:
            spec.enabled = True
        reg.register(spec)
    return reg
