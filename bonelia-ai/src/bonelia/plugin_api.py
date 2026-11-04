"""Stable public API for BONELİA AI adapter packages.

Adapter packages must import ONLY from this module (enforced by tests), so the
core can evolve internally without breaking adapters, and adapters can be added
or removed without touching the core.

Minimal adapter package:

    # pyproject.toml
    [project.entry-points."bonelia.adapters"]
    myapp = "bonelia_adapter_myapp:PLUGIN"

    # bonelia_adapter_myapp/__init__.py
    from bonelia.plugin_api import AdapterManifest, ServerAdapter
    class MyAdapter(ServerAdapter): ...
    class _Plugin:
        manifest = AdapterManifest(adapter_id="myapp", ...)
        def create(self, config, env): return MyAdapter(...) or None
    PLUGIN = _Plugin()
"""

from __future__ import annotations

from .adapters.base import CAPABILITY_KEYS, AdapterManifest, AdapterPlugin, ServerAdapter
from .contracts import AppIdentity, DiagnosticEvent, ErrorCategory, Evidence, RiskLevel, Severity
from .repair.tools import ExecResult, ParamSpec, ToolSpec
from .security.redact import redact_text, redact_value

PLUGIN_API_VERSION = "1"

__all__ = [
    "PLUGIN_API_VERSION", "CAPABILITY_KEYS", "AdapterManifest", "AdapterPlugin", "ServerAdapter",
    "AppIdentity", "DiagnosticEvent", "ErrorCategory", "Evidence", "RiskLevel", "Severity",
    "ExecResult", "ParamSpec", "ToolSpec", "redact_text", "redact_value",
]
