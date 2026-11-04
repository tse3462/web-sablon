"""Test-only adapter plugins that exercise the generic adapter mechanism.

They use only `bonelia.plugin_api` — exactly like a real, separately installed
adapter package — so the core is tested without any real application adapter.
"""

from __future__ import annotations

from typing import Any, Mapping

from bonelia.plugin_api import (
    AdapterManifest, AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, ExecResult, RiskLevel, ServerAdapter, Severity,
    ToolSpec,
)


def manifest(adapter_id: str, secret_env: list[str] | None = None) -> AdapterManifest:
    return AdapterManifest(
        adapter_id=adapter_id, name=f"Demo {adapter_id}", version="0.0.1", status="implemented", runs_on="server",
        capabilities={k: k in ("health_check", "read_only_ops") for k in (
            "recognize", "version_check", "find_logs", "api_connection", "health_check", "read_only_ops", "safe_interventions",
            "intervention_verification")},
        supported_app_versions="test", required_permissions=[], secret_env=secret_env or [])


class DemoAdapter(ServerAdapter):
    def __init__(self, adapter_id: str, fail: bool = False, extra_tools: list[ToolSpec] | None = None):
        self.manifest = manifest(adapter_id)
        self.fail = fail
        self.extra_tools = extra_tools or []
        self.calls = 0

    def health(self, lang: str = "tr") -> tuple[list[DiagnosticEvent], dict[str, str]]:
        self.calls += 1
        if self.fail:
            raise RuntimeError("adapter crashed")
        app = AppIdentity(app_id=self.manifest.adapter_id, name=self.manifest.name, adapter_id=self.manifest.adapter_id, recognized=True)
        ev = DiagnosticEvent(app=app, category=ErrorCategory.integration, severity=Severity.error, title="Export queue stalled",
                             fingerprint=f"{self.manifest.adapter_id}-queue", rule_id=f"{self.manifest.adapter_id}.queue",
                             evidence=[Evidence(source=f"{self.manifest.adapter_id}:health", kind="health_check", code="queue",
                                                data={"stalled": 4})])
        return [ev], {f"{self.manifest.adapter_id}:health": "ok"}

    def tools(self) -> list[ToolSpec]:
        return self.extra_tools


def tool(tool_id: str, level: RiskLevel = RiskLevel.SAFE_AUTO) -> ToolSpec:
    return ToolSpec(tool_id=tool_id, description="demo", platforms=("server",), risk_level=level, required_scope="repair:demo",
                    required_role="operator", params={}, supports_dry_run=True, idempotent=True, rollback="n/a", timeout_s=5,
                    max_runs_per_hour=3, verification="demo", side_effects="none",
                    executor=lambda p, d: ExecResult(True, {"dry_run": d}), verifier=lambda p, r: True)


class Plugin:
    def __init__(self, adapter_id: str, *, create_raises: bool = False, returns_none: bool = False, health_fails: bool = False,
                 secret_env: list[str] | None = None, tools: list[ToolSpec] | None = None):
        self.manifest = manifest(adapter_id, secret_env)
        self.create_raises, self.returns_none, self.health_fails, self.tools = create_raises, returns_none, health_fails, tools
        self.seen_config: dict[str, Any] | None = None
        self.seen_env: dict[str, str] | None = None

    def create(self, config: Mapping[str, Any], env: Mapping[str, str]):
        self.seen_config, self.seen_env = dict(config), dict(env)
        if self.create_raises:
            raise RuntimeError("init failed")
        if self.returns_none:
            return None
        return DemoAdapter(self.manifest.adapter_id, fail=self.health_fails, extra_tools=self.tools)


class EntryPoint:
    """Mimics importlib.metadata.EntryPoint."""

    def __init__(self, name: str, plugin: Any = None, load_error: Exception | None = None):
        self.name, self.plugin, self.load_error = name, plugin, load_error

    def load(self):
        if self.load_error:
            raise self.load_error
        return self.plugin
