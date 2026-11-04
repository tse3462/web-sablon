"""Repair policy engine — deterministic, never influenced by AI output.

The policy context is built by the server from its own database (tenant settings,
device scopes, approvals). Nothing in a request body or a model answer can raise
a permission level.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..contracts import RiskLevel, utcnow
from .tools import ToolSpec

# Level 3 (critical) is hard-blocked in v0.1 regardless of configuration.
HARD_MAX_LEVEL = RiskLevel.ADMIN_APPROVED


def params_hash(tool_id: str, params: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([tool_id, params], sort_keys=True, default=str).encode("utf-8")).hexdigest()


@dataclass
class Approval:
    approval_id: str
    tenant_id: str
    tool_id: str
    params_hash: str
    approved_by: str
    expires_at: datetime
    used: bool = False


@dataclass
class PolicyContext:
    tenant_id: str
    device_scopes: set[str]
    actor_role: str  # "operator" | "admin"
    tenant_max_level: RiskLevel  # configured by the customer; default READ_ONLY
    auto_tools: set[str]  # level-1 tools this tenant explicitly allowed to run automatically
    runs_last_hour: int
    approval: Approval | None = None
    environment: str = "test"  # "test" | "production"
    production_writes_allowed: bool = False


@dataclass
class Decision:
    allowed: bool
    dry_run_only: bool
    requires_approval: bool
    reasons: list[str] = field(default_factory=list)


def evaluate(tool: ToolSpec | None, params: dict[str, Any], dry_run: bool, ctx: PolicyContext) -> Decision:
    def deny(reason: str) -> Decision:
        return Decision(False, False, False, [reason])

    if tool is None:
        return deny("unknown_tool")
    if tool.risk_level >= RiskLevel.CRITICAL or tool.risk_level > HARD_MAX_LEVEL:
        return deny("critical_blocked_v0_1")
    try:
        tool.validate_params(params)
    except ValueError as exc:
        return deny(f"invalid_parameters:{exc}")
    if tool.required_scope not in ctx.device_scopes:
        return deny("missing_scope")

    # Read-only tools and dry-runs never change anything; still bounded by scope above.
    if tool.risk_level == RiskLevel.READ_ONLY:
        return Decision(tool.enabled, False, False, ["read_only"] if tool.enabled else ["tool_disabled"])
    if dry_run:
        if not tool.supports_dry_run:
            return deny("dry_run_not_supported")
        return Decision(True, True, False, ["dry_run"])

    # ----- real execution from here on
    if not tool.enabled:
        return deny("tool_disabled")
    if tool.executor is None or tool.verifier is None:
        return deny("no_verified_executor")
    if tool.risk_level > ctx.tenant_max_level:
        return deny("tenant_level_exceeded")
    if ctx.environment == "production" and not ctx.production_writes_allowed:
        return deny("production_writes_not_approved")
    if ctx.runs_last_hour >= tool.max_runs_per_hour:
        return deny("rate_limited")

    # Admin-role tools run only for an admin actor or with a single-use admin approval.
    needs_admin = tool.required_role == "admin" and ctx.actor_role != "admin"
    if tool.risk_level == RiskLevel.SAFE_AUTO and not needs_admin:
        if not tool.idempotent:
            return deny("not_idempotent")
        if tool.tool_id in ctx.auto_tools:
            return Decision(True, False, False, ["auto_allowed"])
        # level-1 tool not on the tenant's auto list: needs an explicit approval like level 2
    ap = ctx.approval
    if ap is None:
        return Decision(False, False, True, ["approval_required"])
    if ap.tenant_id != ctx.tenant_id or ap.tool_id != tool.tool_id:
        return deny("approval_mismatch")
    if ap.params_hash != params_hash(tool.tool_id, params):
        return deny("approval_params_mismatch")
    if ap.used:
        return deny("approval_already_used")
    if ap.expires_at <= utcnow():
        return deny("approval_expired")
    return Decision(True, False, False, ["approved"])
