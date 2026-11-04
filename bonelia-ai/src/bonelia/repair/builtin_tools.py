"""Built-in tool catalogue for v0.1.

Every tool that can change state is DISABLED by default. Enabling one requires
server configuration by the owner; level-3 tools do not exist in v0.1.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..adapters.veedelkorb import VeedelKorbAdapter
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


class VeedelKorbSafeAction:
    """Wraps VeedelKorb's own allow-listed `ai_safe_action('retry_failed_notifications')` RPC.

    Only constructed for an environment explicitly marked as TEST. Production use
    requires a separate, explicit owner approval (see docs/VEEDELKORB.md).
    """

    def __init__(self, supabase_url: str, service_key: str, health: VeedelKorbAdapter, environment: str,
                 transport: httpx.BaseTransport | None = None):
        if environment != "test":
            raise PermissionError("VeedelKorb repair executor may only be configured for a TEST environment in v0.1")
        self.url = supabase_url.rstrip("/")
        self._key = service_key
        self.health = health
        self._client = httpx.Client(timeout=20.0, transport=transport)

    def _failed_24h(self) -> int | None:
        status, body = self.health.fetch()
        if not isinstance(body, dict):
            return None
        n = ((body.get("context") or {}).get("notifications") or {}).get("failed_24h")
        return int(n) if isinstance(n, (int, float)) else None

    def executor(self, params: dict[str, Any], dry_run: bool) -> ExecResult:
        before = self._failed_24h()
        if dry_run:
            return ExecResult(True, {"failed_24h_before": before, "would_requeue_max": 50,
                                     "rpc": "ai_safe_action('retry_failed_notifications')"})
        r = self._client.post(f"{self.url}/rest/v1/rpc/ai_safe_action",
                              headers={"apikey": self._key, "Authorization": f"Bearer {self._key}"},
                              json={"p_action": "retry_failed_notifications", "p_note": "BONELIA AI gateway"})
        try:
            body = r.json()
        except ValueError:
            body = {}
        ok = r.status_code == 200 and isinstance(body, dict) and body.get("ok") is not False
        return ExecResult(ok, {"http_status": r.status_code, "failed_24h_before": before,
                               "result": body if isinstance(body, dict) else {}})

    def verifier(self, params: dict[str, Any], result: ExecResult) -> bool:
        before = result.detail.get("failed_24h_before")
        after = self._failed_24h()
        result.detail["failed_24h_after"] = after
        return before is not None and after is not None and after < before


def veedelkorb_retry_tool(action: VeedelKorbSafeAction | None) -> ToolSpec:
    return ToolSpec(
        tool_id="veedelkorb.retry_failed_notifications",
        description="Re-queue notifications that failed in the last 24 h (each at most once; VeedelKorb's own safe action)",
        platforms=("server",), risk_level=RiskLevel.SAFE_AUTO, required_scope="repair:veedelkorb", required_role="operator",
        params={}, supports_dry_run=True, idempotent=True,
        rollback="Not needed: notifications are re-queued once (ai_retried flag); no order/payment data is touched",
        timeout_s=30, max_runs_per_hour=3,
        verification="notifications.failed_24h from saglik?context=agent decreases after execution",
        side_effects="Customers may receive a previously failed notification",
        executor=action.executor if action else None, verifier=action.verifier if action else None,
        enabled=False)


def default_registry(veedelkorb_action: VeedelKorbSafeAction | None = None,
                     enable: set[str] | None = None) -> ToolRegistry:
    reg = ToolRegistry()
    for spec in (_snapshot_tool(), _restart_service_tool(), veedelkorb_retry_tool(veedelkorb_action)):
        if enable and spec.tool_id in enable and spec.risk_level < RiskLevel.CRITICAL:
            spec.enabled = True
        reg.register(spec)
    return reg
