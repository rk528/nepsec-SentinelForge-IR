"""Request and response schemas."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

T = TypeVar("T")

Severity = Literal["informational", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
IncidentStatus = Literal["new", "open", "investigating", "contained", "resolved", "closed"]
Verdict = Literal["true_positive", "benign_positive", "false_positive", "undetermined"]
AlertStatus = Literal["new", "acknowledged", "escalated", "closed"]
Role = Literal["viewer", "analyst", "lead", "admin"]

EVENT_TYPES = (
    "auth.success",
    "auth.failure",
    "process.start",
    "iam.user_created",
    "iam.group_member_added",
    "log.cleared",
    "service.stopped",
    "network.connection",
    "dns.query",
    "proxy.request",
    "email.delivered",
    "file.created",
    "security.alert",
    "process.access",
    "registry.set",
    "task.created",
)
EventType = Literal[
    "auth.success",
    "auth.failure",
    "process.start",
    "iam.user_created",
    "iam.group_member_added",
    "log.cleared",
    "service.stopped",
    "network.connection",
    "dns.query",
    "proxy.request",
    "email.delivered",
    "file.created",
    "security.alert",
    "process.access",
    "registry.set",
    "task.created",
]


# Syntactic check only. Deliverability checks would reject internal and reserved
# domains that self-hosted deployments legitimately use.
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class ErrorBody(BaseModel):
    detail: str


# --- auth -------------------------------------------------------------------


class LoginIn(BaseModel):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class DemoLoginIn(BaseModel):
    role: Literal["analyst", "lead", "viewer"] = "analyst"


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    org_id: uuid.UUID
    org_name: str
    is_demo: bool
    csrf_token: str | None = None


# --- events -----------------------------------------------------------------

MAX_RAW_KEYS = 200


def _clean_ip(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


class EventIn(BaseModel):
    """A normalised event as accepted by the ingestion API."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_time: datetime
    event_type: EventType
    outcome: str | None = Field(default=None, max_length=32)
    host: str | None = Field(default=None, max_length=255)
    user_name: str | None = Field(default=None, max_length=255)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    domain: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    process_name: str | None = Field(default=None, max_length=255)
    command_line: str | None = Field(default=None, max_length=8192)
    parent_process: str | None = Field(default=None, max_length=255)
    file_hash: str | None = Field(default=None, max_length=128)
    target_user: str | None = Field(default=None, max_length=255)
    group_name: str | None = Field(default=None, max_length=255)
    email_sender: str | None = Field(default=None, max_length=320)
    email_subject: str | None = Field(default=None, max_length=500)
    bytes_out: int | None = Field(default=None, ge=0)
    message: str | None = Field(default=None, max_length=4000)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return _clean_ip(v)

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str | None) -> str | None:
        return v.lower().rstrip(".") if v else v

    @field_validator("event_time")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("event_time must include a timezone offset (UTC recommended)")
        v = v.astimezone(UTC)
        if v > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("event_time is in the future")
        return v

    @field_validator("raw")
    @classmethod
    def _raw_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > MAX_RAW_KEYS:
            raise ValueError(f"raw may contain at most {MAX_RAW_KEYS} top-level keys")
        return v


class IngestIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)
    run_detection: bool = True


class IngestOut(BaseModel):
    received: int
    inserted: int
    duplicates: int
    alerts_created: int
    alerts_updated: int
    skipped: int = 0


class EventOut(ORM):
    id: uuid.UUID
    event_time: datetime
    ingested_at: datetime
    event_type: str
    outcome: str | None
    host: str | None
    user_name: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    domain: str | None
    url: str | None
    process_name: str | None
    command_line: str | None
    parent_process: str | None
    file_hash: str | None
    target_user: str | None
    group_name: str | None
    email_sender: str | None
    email_subject: str | None
    bytes_out: int | None
    message: str | None
    is_synthetic: bool
    scenario_id: str | None
    data_source_id: uuid.UUID
    data_source_name: str | None = None
    raw: dict[str, Any] | None = None  # only populated for analyst+ roles


# --- alerts -------------------------------------------------------------------


class AlertOut(ORM):
    id: uuid.UUID
    rule_id: str
    rule_name: str | None = None
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    status: AlertStatus
    disposition: Verdict | None
    disposition_reason: str | None
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    entities: dict[str, Any]
    evidence_summary: dict[str, Any]
    incident_id: uuid.UUID | None
    incident_number: int | None = None
    assignee_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class AlertTriageIn(BaseModel):
    status: AlertStatus | None = None
    disposition: Verdict | None = None
    disposition_reason: str | None = Field(default=None, max_length=4000)
    assignee_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _closing_requires_disposition(self) -> AlertTriageIn:
        if self.status == "closed" and (not self.disposition or not self.disposition_reason):
            raise ValueError("closing an alert requires a disposition and a reason")
        if self.disposition and not self.disposition_reason:
            raise ValueError("a disposition requires a reason")
        return self


class AlertEscalateIn(BaseModel):
    incident_id: uuid.UUID | None = None  # link to existing incident, or create new when omitted
    title: str | None = Field(default=None, max_length=300)


class DetectionRunIn(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)


# --- incidents ---------------------------------------------------------------


class UserRef(ORM):
    id: uuid.UUID
    display_name: str
    email: str
    role: Role


class IncidentOut(ORM):
    id: uuid.UUID
    number: int
    reference: str
    title: str
    summary: str
    severity: Severity
    status: IncidentStatus
    verdict: Verdict | None
    closure_reason: str | None
    source: str
    tags: list[str]
    assignee: UserRef | None = None
    is_synthetic: bool
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    version: int
    alert_count: int = 0
    event_count: int = 0


class IncidentCreateIn(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    summary: str = Field(default="", max_length=10000)
    severity: Severity
    tags: list[str] = Field(default_factory=list, max_length=20)
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        cleaned = sorted({t.strip().lower()[:64] for t in v if t.strip()})
        return cleaned


class IncidentUpdateIn(BaseModel):
    version: int = Field(ge=1, description="Current version, for optimistic concurrency")
    title: str | None = Field(default=None, min_length=3, max_length=300)
    summary: str | None = Field(default=None, max_length=10000)
    severity: Severity | None = None
    assignee_id: uuid.UUID | None = None
    clear_assignee: bool = False
    tags: list[str] | None = Field(default=None, max_length=20)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted({t.strip().lower()[:64] for t in v if t.strip()})


class IncidentTransitionIn(BaseModel):
    version: int = Field(ge=1)
    status: IncidentStatus
    verdict: Verdict | None = None
    closure_reason: str | None = Field(default=None, max_length=4000)
    reason: str | None = Field(default=None, max_length=2000, description="Required when reopening")


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=10000)
    note_type: Literal["analyst", "assessment"] = "analyst"


class NoteOut(ORM):
    id: uuid.UUID
    note_type: str
    body: str
    created_at: datetime
    author: UserRef | None = None


class LinkEventsIn(BaseModel):
    event_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    reason: str | None = Field(default=None, max_length=300)


class EvidenceOut(ORM):
    id: uuid.UUID
    evidence_type: str
    title: str
    description: str | None
    source_ref: str | None
    provenance: dict[str, Any]
    content: dict[str, Any]
    sha256: str
    created_at: datetime


class TimelineItem(BaseModel):
    at: datetime
    kind: Literal["event", "alert", "note", "status", "action", "evidence", "audit"]
    title: str
    detail: str | None = None
    ref_id: str | None = None
    severity: str | None = None
    actor: str | None = None


class AuditOut(ORM):
    id: uuid.UUID
    actor_label: str
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    ip: str | None
    request_id: str | None
    created_at: datetime


# --- threat intel -------------------------------------------------------------


class IocLookupIn(BaseModel):
    value: str = Field(min_length=1, max_length=2048)
    incident_id: uuid.UUID | None = None
    force_refresh: bool = False


class IocVerdictIn(BaseModel):
    analyst_verdict: Literal["unknown", "benign", "suspicious", "malicious"]
    analyst_note: str = Field(min_length=3, max_length=4000)


class EnrichmentOut(ORM):
    id: uuid.UUID
    provider: str
    status: str
    reported_verdict: str
    score: float | None
    confidence: str | None
    summary: dict[str, Any]
    error: str | None
    fetched_at: datetime
    expires_at: datetime | None


class IndicatorOut(ORM):
    id: uuid.UUID
    ioc_type: str
    value: str
    analyst_verdict: str
    analyst_note: str | None
    first_seen: datetime
    last_looked_up: datetime | None
    lookup_count: int


# --- response -------------------------------------------------------------------


class PlaybookRunIn(BaseModel):
    incident_id: uuid.UUID
    idempotency_key: str = Field(min_length=8, max_length=100, pattern=r"^[A-Za-z0-9_\-:.]+$")
    parameters: dict[str, Any] = Field(default_factory=dict)


class ApprovalIn(BaseModel):
    decision: Literal["approved", "rejected"]
    reason: str = Field(min_length=3, max_length=2000)


class ResponseActionOut(ORM):
    id: uuid.UUID
    incident_id: uuid.UUID
    incident_number: int | None = None
    playbook_run_id: uuid.UUID | None
    action_type: str
    parameters: dict[str, Any]
    requested_by: uuid.UUID | None
    requested_by_name: str | None = None
    status: str
    requires_approval: bool
    simulated: bool
    result: dict[str, Any]
    error: str | None
    rollback_plan: str | None
    created_at: datetime
    updated_at: datetime
    executed_at: datetime | None
    approval: dict[str, Any] | None = None


# --- admin ---------------------------------------------------------------------


class UserCreateIn(BaseModel):
    email: Email
    display_name: str = Field(min_length=1, max_length=120)
    role: Role
    password: str = Field(min_length=12, max_length=256)


class UserUpdateIn(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class DataSourceCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    source_type: Literal[
        "windows_security", "sysmon", "linux_auditd", "firewall", "dns", "proxy", "email_gateway", "edr", "microsoft_entra", "microsoft_defender", "fortigate", "custom"
    ]
    description: str | None = Field(default=None, max_length=2000)
