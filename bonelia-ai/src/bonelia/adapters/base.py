"""Adapter contract. Each supported application plugs into the common core through
one adapter; the core is never rewritten per application (Master prompt §6).

Application-specific adapters are separate, optional packages discovered via the
`bonelia.adapters` entry-point group (see `registry.py`). The core never imports
them by name and must keep working when none is installed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Protocol

from ..contracts import AppIdentity, DiagnosticEvent

CAPABILITY_KEYS = (
    "recognize", "version_check", "find_logs", "api_connection", "health_check",
    "read_only_ops", "safe_interventions", "intervention_verification",
)


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    name: str
    version: str
    status: str  # "implemented" | "planned"
    runs_on: str  # "client" (USB/agent) | "server"
    capabilities: dict[str, bool]
    supported_app_versions: str
    required_permissions: list[str]
    safe_tools: list[str] = field(default_factory=list)
    notes: str = ""
    # Environment variables (server-side secrets) this adapter may read. The core
    # hands an adapter ONLY these variables, and only with the prefix BONELIA_<ID>_.
    secret_env: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Adapter(ABC):
    """Client-side adapter (runs inside the Portable Monitor / Agent)."""

    manifest: AdapterManifest

    @abstractmethod
    def recognize(self, apps: list[AppIdentity]) -> list[AppIdentity]:
        """Return apps this adapter claims (with adapter_id set)."""


class ServerAdapter(ABC):
    """Server-side adapter: talks to an application's official health/API interface."""

    manifest: AdapterManifest

    @abstractmethod
    def health(self, lang: str = "tr") -> tuple[list[DiagnosticEvent], dict[str, str]]:
        """Read-only health evaluation. Returns events and collector status."""

    def tools(self) -> list[Any]:
        """Optional ToolSpecs. Tool ids must start with '<adapter_id>.'; all start disabled."""
        return []


class AdapterPlugin(Protocol):
    """Object an adapter package exposes under the `bonelia.adapters` entry-point group."""

    manifest: AdapterManifest

    def create(self, config: Mapping[str, Any], env: Mapping[str, str]) -> ServerAdapter | None:
        """Return a configured adapter, or None if configuration/secrets are missing."""
