"""Universal built-in tool catalogue for v0.1 (application-independent).

Every tool that can change state is DISABLED by default. Application-specific
tools come from optional adapters (namespaced, also disabled by default).
Level-3 tools do not exist in v0.1.
"""

from __future__ import annotations

from typing import Any

from ..contracts import RiskLevel
from .tools import ExecResult, ParamSpec, ToolRegistry, ToolSpec

SERVICE_NAME = r"[A-Za-z0-9_.-]{1,80}"


def _snapshot_tool() -> ToolSpec:
    return ToolSpec(
        tool_id="generic.collect_snapshot", description="Collect read-only system/app snapshot (client side)",
        platforms=("windows", "any"), risk_level=RiskLevel.READ_ONLY, required_scope="diagnose", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True, rollback="n/a (read-only)", timeout_s=60, max_runs_per_hour=60,
        verification="n/a", side_effects="none", enabled=True)


def _restart_service_tool() -> ToolSpec:
    def executor(params: dict[str, Any], dry_run: bool) -> ExecResult:
        if dry_run:
            return ExecResult(True, {"would_run": f"Restart-Service -Name {params['service_name']} (requires admin approval)",
                                     "note": "v0.1: dry-run only; real execution not implemented"})
        return ExecResult(False, {"error": "not_implemented_v0_1"})

    return ToolSpec(
        tool_id="windows.restart_service", description="Restart one named Windows service (allow-listed per tenant)",
        platforms=("windows",), risk_level=RiskLevel.ADMIN_APPROVED, required_scope="repair:windows", required_role="admin",
        params={"service_name": ParamSpec(str, pattern=SERVICE_NAME)}, supports_dry_run=True, idempotent=False,
        rollback="Service returns to previous state on its own; if it fails to start, restore previous configuration",
        timeout_s=120, max_runs_per_hour=2, verification="Service status == Running and app health check passes",
        side_effects="Brief interruption of the service", executor=executor, verifier=None, enabled=False)


def default_registry(enable: set[str] | None = None) -> ToolRegistry:
    reg = ToolRegistry()
    for spec in (_snapshot_tool(), _restart_service_tool()):
        if enable and spec.tool_id in enable and spec.risk_level < RiskLevel.CRITICAL:
            spec.enabled = True
        reg.register(spec)
    return reg
