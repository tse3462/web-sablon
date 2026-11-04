"""Adapter contract. Each supported application plugs into the common core through
one adapter; the core is never rewritten per application (Master prompt §6).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..contracts import AppIdentity, DiagnosticEvent


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

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


CAPABILITY_KEYS = (
    "recognize", "version_check", "find_logs", "api_connection", "health_check",
    "read_only_ops", "safe_interventions", "intervention_verification",
)


class Adapter(ABC):
    manifest: AdapterManifest

    @abstractmethod
    def recognize(self, apps: list[AppIdentity]) -> list[AppIdentity]:
        """Return apps this adapter claims (with adapter_id set)."""

    def health(self) -> tuple[list[DiagnosticEvent], dict[str, str]]:
        """Read-only health evaluation. Returns events and collector status."""
        return [], {self.manifest.adapter_id: "unavailable:not_supported"}
