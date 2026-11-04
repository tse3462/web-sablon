import time
from datetime import timedelta

import pytest

from bonelia.contracts import OutcomeState, RiskLevel, utcnow
from bonelia.repair.builtin_tools import default_registry
from bonelia.repair.gateway import ToolGateway
from bonelia.repair.policy import Approval, PolicyContext, evaluate, params_hash
from bonelia.repair.tools import ExecResult, ParamSpec, ToolRegistry, ToolSpec


class Sandbox:
    """A controlled test system: a job queue with failed jobs."""

    def __init__(self, failed=3):
        self.failed = failed
        self.runs = 0

    def executor(self, params, dry_run):
        if dry_run:
            return ExecResult(True, {"would_retry": self.failed})
        self.runs += 1
        self.failed = 0
        return ExecResult(True, {"retried": True})

    def verifier(self, params, result):
        return self.failed == 0  # independent check of the system state


def tool(level=RiskLevel.SAFE_AUTO, enabled=True, sandbox=None, **kw) -> ToolSpec:
    sb = sandbox or Sandbox()
    base = dict(tool_id="test.retry_jobs", description="retry", platforms=("server",), risk_level=level, required_scope="repair:test",
                required_role="operator", params={"queue": ParamSpec(str, choices=("mail", "sms"))}, supports_dry_run=True,
                idempotent=True, rollback="n/a", timeout_s=2, max_runs_per_hour=3, verification="failed==0", side_effects="resend",
                executor=sb.executor, verifier=sb.verifier, enabled=enabled)
    base.update(kw)
    return ToolSpec(**base)


def ctx(**kw) -> PolicyContext:
    base = dict(tenant_id="t1", device_scopes={"repair:test", "diagnose"}, actor_role="operator", tenant_max_level=RiskLevel.SAFE_AUTO,
                auto_tools={"test.retry_jobs"}, runs_last_hour=0)
    base.update(kw)
    return PolicyContext(**base)


P = {"queue": "mail"}


def test_unknown_tool_denied():
    assert evaluate(None, {}, False, ctx()).reasons == ["unknown_tool"]


def test_level3_is_hard_blocked_even_if_enabled_and_approved():
    t = tool(level=RiskLevel.CRITICAL)
    ap = Approval("a", "t1", t.tool_id, params_hash(t.tool_id, P), "admin", utcnow() + timedelta(minutes=5))
    d = evaluate(t, P, False, ctx(tenant_max_level=RiskLevel.CRITICAL, approval=ap))
    assert not d.allowed and d.reasons == ["critical_blocked_v0_1"]


@pytest.mark.parametrize("params, reason", [({"queue": "all; rm -rf /"}, "invalid_parameters"), ({}, "invalid_parameters"),
                                            ({"queue": "mail", "extra": 1}, "invalid_parameters")])
def test_parameter_validation(params, reason):
    assert evaluate(tool(), params, False, ctx()).reasons[0].startswith(reason)


def test_scope_and_role_and_tenant_level():
    assert evaluate(tool(), P, False, ctx(device_scopes={"diagnose"})).reasons == ["missing_scope"]
    admin_tool = tool(required_role="admin")
    assert evaluate(admin_tool, P, False, ctx()).requires_approval  # operator needs an admin approval
    assert evaluate(admin_tool, P, True, ctx()).dry_run_only  # but may always dry-run
    assert evaluate(tool(), P, False, ctx(tenant_max_level=RiskLevel.READ_ONLY)).reasons == ["tenant_level_exceeded"]


def test_level1_auto_runs_only_if_tenant_allows():
    assert evaluate(tool(), P, False, ctx()).allowed
    d = evaluate(tool(), P, False, ctx(auto_tools=set()))
    assert not d.allowed and d.requires_approval


def test_disabled_and_unverifiable_tools_cannot_execute_but_can_dry_run():
    assert evaluate(tool(enabled=False), P, False, ctx()).reasons == ["tool_disabled"]
    assert evaluate(tool(verifier=None), P, False, ctx()).reasons == ["no_verified_executor"]
    assert evaluate(tool(enabled=False), P, True, ctx()).dry_run_only


def test_production_writes_require_explicit_permission():
    assert evaluate(tool(), P, False, ctx(environment="production")).reasons == ["production_writes_not_approved"]
    assert evaluate(tool(), P, False, ctx(environment="production", production_writes_allowed=True)).allowed


def test_rate_limit():
    assert evaluate(tool(), P, False, ctx(runs_last_hour=3)).reasons == ["rate_limited"]


def test_level2_approval_rules():
    t = tool(level=RiskLevel.ADMIN_APPROVED, idempotent=False)
    c = ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED)
    assert evaluate(t, P, False, c).requires_approval
    good = Approval("a", "t1", t.tool_id, params_hash(t.tool_id, P), "admin", utcnow() + timedelta(minutes=5))
    assert evaluate(t, P, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, approval=good)).allowed
    for bad, reason in [
        (Approval("a", "t2", t.tool_id, good.params_hash, "admin", good.expires_at), "approval_mismatch"),
        (Approval("a", "t1", t.tool_id, params_hash(t.tool_id, {"queue": "sms"}), "admin", good.expires_at), "approval_params_mismatch"),
        (Approval("a", "t1", t.tool_id, good.params_hash, "admin", good.expires_at, used=True), "approval_already_used"),
        (Approval("a", "t1", t.tool_id, good.params_hash, "admin", utcnow() - timedelta(seconds=1)), "approval_expired"),
    ]:
        assert evaluate(t, P, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, approval=bad)).reasons == [reason]


def test_gateway_executes_verifies_and_audits():
    sb = Sandbox()
    reg = ToolRegistry()
    reg.register(tool(sandbox=sb))
    log = []
    gw = ToolGateway(reg, lambda a, d: log.append(a))
    dry = gw.run("test.retry_jobs", P, True, ctx())
    assert dry.outcome == OutcomeState.dry_run_only and sb.failed == 3 and sb.runs == 0
    res = gw.run("test.retry_jobs", P, False, ctx())
    assert res.outcome == OutcomeState.executed_verified and sb.runs == 1
    assert log == ["tool.start", "tool.dry_run", "tool.start", "tool.executed"]


def test_gateway_reports_unverified_when_independent_check_fails():
    sb = Sandbox()
    reg = ToolRegistry()
    reg.register(tool(sandbox=sb, verifier=lambda p, r: False))
    res = ToolGateway(reg, lambda a, d: None).run("test.retry_jobs", P, False, ctx())
    assert res.outcome == OutcomeState.executed_unverified and res.detail["verified"] is False


def test_gateway_timeout_and_executor_crash_fail_safely():
    reg = ToolRegistry()
    reg.register(tool(executor=lambda p, d: (time.sleep(3), ExecResult(True))[1], timeout_s=1))
    reg.register(tool(tool_id="test.crash", executor=lambda p, d: 1 / 0))
    gw = ToolGateway(reg, lambda a, d: None)
    assert gw.run("test.retry_jobs", P, False, ctx()).detail == {"error": "timeout"}
    assert gw.run("test.crash", P, False, ctx(auto_tools={"test.crash"})).outcome == OutcomeState.failed


def test_approval_consumed_before_execution():
    t = tool(level=RiskLevel.ADMIN_APPROVED)
    reg = ToolRegistry()
    reg.register(t)
    used = []
    ap = Approval("a", "t1", t.tool_id, params_hash(t.tool_id, P), "admin", utcnow() + timedelta(minutes=5))
    ToolGateway(reg, lambda a, d: None).run(t.tool_id, P, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, approval=ap),
                                           on_approval_used=lambda: used.append(1))
    assert used == [1]


def test_builtin_registry_defaults_are_safe():
    reg = default_registry()
    assert {t.tool_id for t in reg.all()} == {"generic.collect_snapshot", "windows.start_service", "windows.restart_service"}
    # Service tools run on the client and are inert until the customer allows repairs (tenant level 0 by default)
    for tid, level in (("windows.start_service", RiskLevel.SAFE_AUTO), ("windows.restart_service", RiskLevel.ADMIN_APPROVED)):
        t = reg.get(tid)
        assert t.runs_on == "client" and t.risk_level == level and t.executor is None
        assert evaluate(t, {"service_name": "Spooler"}, False, ctx(device_scopes={"repair:windows"},
                                                                    tenant_max_level=RiskLevel.READ_ONLY)).reasons == ["tenant_level_exceeded"]
    assert all(t.risk_level < RiskLevel.CRITICAL for t in reg.all())
    with pytest.raises(ValueError):
        reg.register(tool(tool_id="BAD ID"))


def test_client_side_tools_one_click_and_technician_confirmation():
    reg = default_registry()
    start, restart = reg.get("windows.start_service"), reg.get("windows.restart_service")
    p = {"service_name": "Spooler"}
    base = dict(device_scopes={"repair:windows"}, auto_tools={"windows.start_service"})
    # level 1: one click once the customer allowed level 1 (no executor needed on the server)
    assert evaluate(start, p, False, ctx(tenant_max_level=RiskLevel.SAFE_AUTO, **base)).reasons == ["auto_allowed"]
    # level 2: needs customer level 2 AND the technician's confirmation; no remote admin approval
    assert evaluate(restart, p, False, ctx(tenant_max_level=RiskLevel.SAFE_AUTO, technician_confirmed=True, **base)).reasons == ["tenant_level_exceeded"]
    assert evaluate(restart, p, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, **base)).requires_approval
    assert evaluate(restart, p, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, technician_confirmed=True, **base)).allowed
    # injection-shaped names never pass
    assert not evaluate(start, {"service_name": "x; shutdown /s"}, False, ctx(tenant_max_level=RiskLevel.SAFE_AUTO, **base)).allowed
    # level 3 stays blocked even with confirmation
    crit = tool(level=RiskLevel.CRITICAL, runs_on="client")
    assert evaluate(crit, P, False, ctx(tenant_max_level=RiskLevel.ADMIN_APPROVED, technician_confirmed=True)).reasons == ["critical_blocked_v0_1"]


def test_windows_executors_refuse_critical_and_invalid_services():
    from bonelia.repair import windows_tools as wt

    for name in ("RpcSs", "lsass", "WinDefend", "EventLog"):
        assert wt.start_service({"service_name": name}, False).detail["error"] == "critical_service_refused"
        assert wt.restart_service({"service_name": name}, False).detail["error"] == "critical_service_refused"
    assert wt.start_service({"service_name": "a b; del"}, False).detail["error"] == "invalid_service_name"
    assert wt.start_service({"service_name": 5}, False).detail["error"] == "invalid_service_name"
