"""On-site repair: server authorizes -> USB executes locally -> independent check -> audit report.

The technician pressing "Repair" is the trigger. The customer's consent is given once
per customer on the server (`bonelia-server allow-repairs`), not per click. Level-2
actions additionally show the risk text before the click is accepted.
"""

from __future__ import annotations

from typing import Any, Callable

from ..contracts import OutcomeState
from ..repair.builtin_tools import default_registry
from ..repair.tools import ExecResult
from ..repair.windows_tools import EXECUTORS
from .client import ServerClient

Executors = dict[str, tuple[Callable[[dict[str, Any], bool], ExecResult], Callable[[dict[str, Any], ExecResult], bool]]]


def repair(client: ServerClient, tool_id: str, params: dict[str, Any], technician_confirmed: bool,
           executors: Executors | None = None) -> dict[str, Any]:
    executors = EXECUTORS if executors is None else executors
    spec = default_registry().get(tool_id)
    if spec is None or spec.runs_on != "client" or tool_id not in executors:
        return {"tool_id": tool_id, "outcome": OutcomeState.denied.value, "reasons": ["unknown_local_tool"]}
    try:
        spec.validate_params(params)  # same validation as the server, before anything happens
    except ValueError as exc:
        return {"tool_id": tool_id, "outcome": OutcomeState.denied.value, "reasons": [f"invalid_parameters:{exc}"]}
    auth = client.authorize_tool(tool_id, params, technician_confirmed)
    if not auth.get("allowed") or auth.get("dry_run_only") or not auth.get("grant_id"):
        return {"tool_id": tool_id, "outcome": OutcomeState.denied.value, "reasons": auth.get("reasons", []),
                "requires_approval": auth.get("requires_approval", False)}
    executor, verifier = executors[tool_id]
    try:
        result = executor(dict(params), False)
    except Exception as exc:  # never crash the UI because of a repair
        result = ExecResult(False, {"error": type(exc).__name__})
    verified = False
    if result.ok:
        try:
            verified = bool(verifier(dict(params), result))
        except Exception as exc:
            result.detail["verify_error"] = type(exc).__name__
    outcome = (OutcomeState.executed_verified if verified else OutcomeState.executed_unverified) if result.ok else OutcomeState.failed
    detail = {k: v for k, v in result.detail.items() if k in ("before", "after", "exit_code", "error", "note", "verify_error")}
    try:
        client.report_tool(auth["grant_id"], tool_id, params, outcome.value, verified, detail)
    except Exception:
        detail["report"] = "not_delivered"
    return {"tool_id": tool_id, "params": params, "outcome": outcome.value, "verified": verified, "detail": detail,
            "reasons": auth.get("reasons", [])}
