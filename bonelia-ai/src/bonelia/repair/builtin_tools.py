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


def default_registry(enable: set[str] | None = None) -> ToolRegistry:
    reg = ToolRegistry()
    for spec in (_snapshot_tool(), _start_service_tool(), _restart_service_tool()):
        if enable and spec.tool_id in enable and spec.risk_level < RiskLevel.CRITICAL:
            spec.enabled = True
        reg.register(spec)
    return reg
