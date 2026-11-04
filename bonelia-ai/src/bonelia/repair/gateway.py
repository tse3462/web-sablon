"""AI Tool Execution Gateway: permission -> allow list -> params -> approval ->
execute (with timeout) -> independent verification -> audit (Master prompt §21/§22).
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Callable

from ..contracts import OutcomeState
from .policy import Decision, PolicyContext, evaluate
from .tools import ExecResult, ToolRegistry

AuditSink = Callable[[str, dict[str, Any]], None]  # (action, detail)


@dataclass
class GatewayResult:
    outcome: OutcomeState
    decision: Decision
    detail: dict[str, Any] = field(default_factory=dict)


class ToolGateway:
    def __init__(self, registry: ToolRegistry, audit: AuditSink):
        self.registry = registry
        self.audit = audit
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="bonelia-tool")

    def run(self, tool_id: str, params: dict[str, Any], dry_run: bool, ctx: PolicyContext,
            on_approval_used: Callable[[], None] | None = None) -> GatewayResult:
        tool = self.registry.get(tool_id)
        decision = evaluate(tool, params, dry_run, ctx)
        base = {"tool_id": tool_id, "dry_run": dry_run, "tenant_id": ctx.tenant_id, "reasons": decision.reasons}
        if not decision.allowed:
            self.audit("tool.denied", base)
            return GatewayResult(OutcomeState.denied, decision, {"reasons": decision.reasons})
        assert tool is not None
        if tool.executor is None:
            # read-only tool without executor (e.g. metadata tools) — nothing to run
            self.audit("tool.noop", base)
            return GatewayResult(OutcomeState.not_attempted, decision)
        if decision.dry_run_only and on_approval_used is not None:
            on_approval_used = None  # dry-runs never consume approvals
        if not decision.dry_run_only and on_approval_used is not None and "approved" in decision.reasons:
            on_approval_used()  # consume BEFORE executing: a crash cannot allow a second run
        self.audit("tool.start", base)
        fut = self._pool.submit(tool.executor, dict(params), decision.dry_run_only)
        try:
            result: ExecResult = fut.result(timeout=tool.timeout_s)
        except concurrent.futures.TimeoutError:
            self.audit("tool.timeout", base)
            return GatewayResult(OutcomeState.failed, decision, {"error": "timeout"})
        except Exception as exc:  # executor bug: fail safe, never retry automatically
            self.audit("tool.error", {**base, "error": type(exc).__name__})
            return GatewayResult(OutcomeState.failed, decision, {"error": type(exc).__name__})
        if decision.dry_run_only or tool.risk_level == 0:
            self.audit("tool.dry_run" if decision.dry_run_only else "tool.read", {**base, "result": result.detail})
            return GatewayResult(OutcomeState.dry_run_only if decision.dry_run_only else OutcomeState.executed_verified,
                                 decision, result.detail)
        if not result.ok:
            self.audit("tool.failed", {**base, "result": result.detail})
            return GatewayResult(OutcomeState.failed, decision, result.detail)
        verified = False
        try:
            verified = bool(tool.verifier(dict(params), result)) if tool.verifier else False
        except Exception as exc:
            self.audit("tool.verify_error", {**base, "error": type(exc).__name__})
        outcome = OutcomeState.executed_verified if verified else OutcomeState.executed_unverified
        self.audit("tool.executed", {**base, "verified": verified, "result": result.detail})
        return GatewayResult(outcome, decision, {**result.detail, "verified": verified})
