"""Tool registry for the AI Tool Execution Gateway (Master prompt §21).

A tool is the ONLY way anything can change on a system. AI output can at most
name a tool id; the gateway and the policy engine decide everything else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..contracts import RiskLevel


@dataclass(frozen=True)
class ParamSpec:
    type: type
    required: bool = True
    pattern: str | None = None  # for str
    choices: tuple[Any, ...] | None = None
    min: float | None = None
    max: float | None = None

    def validate(self, name: str, value: Any) -> None:
        if not isinstance(value, self.type) or (self.type is int and isinstance(value, bool)):
            raise ValueError(f"parameter '{name}' must be {self.type.__name__}")
        if self.choices is not None and value not in self.choices:
            raise ValueError(f"parameter '{name}' not in allowed values")
        if self.pattern is not None and not re.fullmatch(self.pattern, str(value)):
            raise ValueError(f"parameter '{name}' has an invalid format")
        if self.min is not None and value < self.min:
            raise ValueError(f"parameter '{name}' below minimum")
        if self.max is not None and value > self.max:
            raise ValueError(f"parameter '{name}' above maximum")


@dataclass
class ExecResult:
    ok: bool
    detail: dict[str, Any] = field(default_factory=dict)


Executor = Callable[[dict[str, Any], bool], ExecResult]  # (params, dry_run) -> result
Verifier = Callable[[dict[str, Any], ExecResult], bool]


@dataclass
class ToolSpec:
    tool_id: str
    description: str
    platforms: tuple[str, ...]  # "windows", "server", "any"
    risk_level: RiskLevel
    required_scope: str  # device scope, e.g. "repair:windows" or "repair:<adapter_id>"
    required_role: str  # "operator" | "admin"
    params: dict[str, ParamSpec]
    supports_dry_run: bool
    idempotent: bool
    rollback: str  # human-readable rollback procedure, "n/a" for read-only
    timeout_s: int
    max_runs_per_hour: int
    verification: str  # how success is verified independently
    side_effects: str
    executor: Executor | None = None
    verifier: Verifier | None = None
    enabled: bool = False  # tools are OFF unless explicitly enabled by configuration

    def validate_params(self, params: dict[str, Any]) -> None:
        unknown = set(params) - set(self.params)
        if unknown:
            raise ValueError(f"unknown parameters: {sorted(unknown)}")
        for name, spec in self.params.items():
            if name not in params:
                if spec.required:
                    raise ValueError(f"missing parameter '{name}'")
                continue
            spec.validate(name, params[name])

    def public_manifest(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id, "description": self.description, "platforms": list(self.platforms),
            "risk_level": int(self.risk_level), "required_scope": self.required_scope, "required_role": self.required_role,
            "params": {k: {"type": v.type.__name__, "required": v.required, "choices": list(v.choices) if v.choices else None}
                       for k, v in self.params.items()},
            "supports_dry_run": self.supports_dry_run, "idempotent": self.idempotent, "rollback": self.rollback,
            "timeout_s": self.timeout_s, "max_runs_per_hour": self.max_runs_per_hour, "verification": self.verification,
            "side_effects": self.side_effects, "enabled": self.enabled,
            "executable": self.executor is not None and self.verifier is not None,
        }


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.tool_id in self._tools:
            raise ValueError(f"tool already registered: {spec.tool_id}")
        if not re.fullmatch(r"[a-z0-9-]+\.[a-z0-9_.-]+", spec.tool_id):
            raise ValueError("tool id must look like 'namespace.action'")
        self._tools[spec.tool_id] = spec

    def get(self, tool_id: str) -> ToolSpec | None:
        return self._tools.get(tool_id)

    def ids(self, enabled_only: bool = True) -> set[str]:
        return {t.tool_id for t in self._tools.values() if t.enabled or not enabled_only}

    def all(self) -> list[ToolSpec]:
        return list(self._tools.values())
