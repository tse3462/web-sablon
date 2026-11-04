"""Shared, versioned data contracts used by the Portable Monitor, Agent and Server.

Every structure that crosses a process or network boundary is defined here so the
client and the server can never drift apart. All models forbid unknown fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


# --------------------------------------------------------------------------- enums


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class ErrorCategory(str, Enum):
    app_crash = "app_crash"
    app_hang = "app_hang"
    service_failure = "service_failure"
    connectivity = "connectivity"
    database = "database"
    disk = "disk"
    resource_exhaustion = "resource_exhaustion"
    scheduled_job = "scheduled_job"
    integration = "integration"
    payment = "payment"
    invoice = "invoice"
    order = "order"
    notification = "notification"
    os_stability = "os_stability"
    configuration = "configuration"
    unknown = "unknown"


class RiskLevel(IntEnum):
    """Intervention levels (Master prompt §13)."""

    READ_ONLY = 0
    SAFE_AUTO = 1
    ADMIN_APPROVED = 2
    CRITICAL = 3


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class ApprovalState(str, Enum):
    not_required = "not_required"
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    blocked = "blocked"


class OutcomeState(str, Enum):
    not_attempted = "not_attempted"
    dry_run_only = "dry_run_only"
    executed_verified = "executed_verified"
    executed_unverified = "executed_unverified"
    failed = "failed"
    denied = "denied"


# --------------------------------------------------------------------------- evidence


class Evidence(_Model):
    """A single piece of technical evidence. `text` is UNTRUSTED data."""

    source: str = Field(max_length=120)  # e.g. "windows_event_log:Application"
    kind: str = Field(max_length=60)  # e.g. "event", "metric", "health_check", "log_line"
    observed_at: datetime | None = None
    code: str | None = Field(default=None, max_length=120)  # event id / error code
    text: str = Field(default="", max_length=4000)
    data: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = False


class AppIdentity(_Model):
    app_id: str = Field(max_length=120)  # stable id, e.g. "win:notepad.exe" or an adapter app id
    name: str = Field(max_length=200)
    publisher: str | None = Field(default=None, max_length=200)
    version: str | None = Field(default=None, max_length=80)
    adapter_id: str = Field(default="generic-windows", max_length=80)
    recognized: bool = False  # True when a dedicated adapter recognises the app


class DiagnosticEvent(_Model):
    """Structured error event (Master prompt §11)."""

    contract_version: str = CONTRACT_VERSION
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    tenant_id: str | None = None
    device_id: str | None = None
    app: AppIdentity
    category: ErrorCategory = ErrorCategory.unknown
    severity: Severity = Severity.error
    title: str = Field(max_length=300)
    occurred_at: datetime = Field(default_factory=utcnow)
    fingerprint: str = Field(max_length=64)
    occurrences: int = 1
    evidence: list[Evidence] = Field(default_factory=list, max_length=50)
    rule_id: str | None = None


class Hypothesis(_Model):
    cause: str = Field(max_length=1000)
    confidence: Confidence
    supporting_evidence: list[str] = Field(default_factory=list, max_length=20)


class RecommendedAction(_Model):
    """A recommendation. `tool_id` must exist in the tool registry or it is ignored."""

    description: str = Field(max_length=1000)
    tool_id: str | None = Field(default=None, max_length=120)
    parameters: dict[str, Any] = Field(default_factory=dict)
    manual: bool = True  # True => a human performs it; nothing executes


class Diagnosis(_Model):
    event_id: str
    produced_by: str  # "rules", "ollama:<model>", "openai:<model>", ...
    summary: str = Field(max_length=2000)
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=10)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    recommendations: list[RecommendedAction] = Field(default_factory=list, max_length=10)
    is_definitive: bool = False  # AI output is never allowed to set this to True
    warnings: list[str] = Field(default_factory=list)


class SystemSnapshot(_Model):
    hostname_ref: str  # hashed, never the raw hostname
    os: str
    os_version: str
    cpu_count: int | None = None
    cpu_percent: float | None = None
    memory_total_mb: int | None = None
    memory_used_percent: float | None = None
    disks: list[dict[str, Any]] = Field(default_factory=list)
    uptime_s: int | None = None
    is_windows: bool = False


class ScanResult(_Model):
    contract_version: str = CONTRACT_VERSION
    scan_id: str = Field(default_factory=lambda: new_id("scan"))
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    mode: str = "quick"
    system: SystemSnapshot | None = None
    apps: list[AppIdentity] = Field(default_factory=list)
    events: list[DiagnosticEvent] = Field(default_factory=list)
    collector_status: dict[str, str] = Field(default_factory=dict)  # name -> ok|unavailable|error:...
    diagnoses: list[Diagnosis] = Field(default_factory=list)


# --------------------------------------------------------------------------- network


class EnrollRequest(_Model):
    enrollment_code: str = Field(min_length=16, max_length=128)
    device_label: str = Field(max_length=80)
    public_key_b64: str = Field(max_length=200)
    client_version: str = Field(max_length=40)


class EnrollResponse(_Model):
    device_id: str
    tenant_id: str
    scopes: list[str]
    server_public_key_b64: str


class AnalyzeRequest(_Model):
    contract_version: str = CONTRACT_VERSION
    events: list[DiagnosticEvent] = Field(max_length=25)
    system: SystemSnapshot | None = None
    allow_cloud: bool = False  # customer consent for cloud AI, requested by the operator
    language: str = Field(default="tr", pattern="^(tr|de|en)$")


class AnalyzeResponse(_Model):
    diagnoses: list[Diagnosis]
    ai_mode: str
    notices: list[str] = Field(default_factory=list)


class ToolRequest(_Model):
    tool_id: str = Field(max_length=120)
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    event_id: str | None = None
    approval_id: str | None = None
