"""ORM models.

Every tenant-owned table carries ``org_id`` and every query in the routers is
filtered by the caller's organisation. Enumerations are stored as text with
CHECK constraints so they stay readable in SQL and are cheap to migrate.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

# --- enumerations ---------------------------------------------------------

ROLES = ("viewer", "analyst", "lead", "admin")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
INCIDENT_STATUSES = ("new", "open", "investigating", "contained", "resolved", "closed")
VERDICTS = ("true_positive", "benign_positive", "false_positive", "undetermined")
ALERT_STATUSES = ("new", "acknowledged", "escalated", "closed")
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
ACTION_STATUSES = ("pending_approval", "approved", "rejected", "executed", "failed", "cancelled")
EVIDENCE_TYPES = ("event", "alert", "ioc_enrichment", "playbook_output", "analyst_observation", "report")
NOTE_TYPES = ("analyst", "assessment", "system")


def _check(column: str, values: tuple[str, ...], name: str) -> CheckConstraint:
    quoted = ", ".join(f"'{v}'" for v in values)
    return CheckConstraint(f"{column} IN ({quoted})", name=name)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)


# --- identity and tenancy -------------------------------------------------


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    incident_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = _created_at()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        _check("role", ROLES, "ck_users_role"),
        Index("uq_users_email_lower", func.lower(text("email")), unique=True),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    # NULL for demo users: they can only sign in through demo mode.
    password_hash: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = _created_at()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set when an administrator removes the account (see migration 0002).
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization] = relationship(lazy="joined")


class UserSession(Base):
    __tablename__ = "user_sessions"
    __table_args__ = (Index("ix_user_sessions_user", "user_id"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))

    user: Mapped[User] = relationship(lazy="joined")


# --- telemetry ------------------------------------------------------------


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "hostname", name="uq_assets_org_hostname"),
        _check("criticality", ("low", "medium", "high", "critical"), "ck_assets_criticality"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False, default="workstation")
    os: Mapped[str | None] = mapped_column(String(80))
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    owner: Mapped[str | None] = mapped_column(String(120))
    ip_addresses: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    first_seen: Mapped[datetime] = _created_at()
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_telemetry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DataSource(Base):
    __tablename__ = "data_sources"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_data_sources_org_name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Only a SHA-256 of the ingest key is stored; the key is shown once on creation.
    ingest_key_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    ingest_key_prefix: Mapped[str | None] = mapped_column(String(16))
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    event_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created_at()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint", name="uq_events_org_fingerprint"),
        Index("ix_events_org_time", "org_id", "event_time"),
        Index("ix_events_org_type_time", "org_id", "event_type", "event_time"),
        Index("ix_events_org_host", "org_id", "host"),
        Index("ix_events_org_user", "org_id", "user_name"),
        Index("ix_events_org_src_ip", "org_id", "src_ip"),
        Index("ix_events_org_dst_ip", "org_id", "dst_ip"),
        Index("ix_events_org_domain", "org_id", "domain"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    data_source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("data_sources.id"), nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"))
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = _created_at()
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(32))
    host: Mapped[str | None] = mapped_column(String(255))
    user_name: Mapped[str | None] = mapped_column(String(255))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    domain: Mapped[str | None] = mapped_column(String(255))
    url: Mapped[str | None] = mapped_column(Text)
    process_name: Mapped[str | None] = mapped_column(String(255))
    command_line: Mapped[str | None] = mapped_column(Text)
    parent_process: Mapped[str | None] = mapped_column(String(255))
    file_hash: Mapped[str | None] = mapped_column(String(128))
    target_user: Mapped[str | None] = mapped_column(String(255))
    group_name: Mapped[str | None] = mapped_column(String(255))
    email_sender: Mapped[str | None] = mapped_column(String(320))
    email_subject: Mapped[str | None] = mapped_column(String(500))
    bytes_out: Mapped[int | None] = mapped_column(BigInteger)
    message: Mapped[str | None] = mapped_column(Text)
    # Raw payload as received. Untrusted: never rendered as HTML or executed.
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scenario_id: Mapped[str | None] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    data_source: Mapped[DataSource] = relationship(lazy="raise")


# --- detection ------------------------------------------------------------


class DetectionRule(Base):
    """Metadata mirror of the rules defined in code (app/detection/rules.py)."""

    __tablename__ = "detection_rules"
    __table_args__ = (_check("severity", SEVERITIES, "ck_detection_rules_severity"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    required_telemetry: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    false_positives: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    attack_techniques: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DetectionTestRun(Base):
    __tablename__ = "detection_test_runs"
    __table_args__ = (Index("ix_detection_test_runs_rule_time", "rule_id", "run_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    rule_id: Mapped[str] = mapped_column(String(32), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    run_at: Mapped[datetime] = _created_at()
    true_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    true_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    precision: Mapped[float | None] = mapped_column(Float)
    recall: Mapped[float | None] = mapped_column(Float)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("org_id", "dedup_key", name="uq_alerts_org_dedup"),
        _check("severity", SEVERITIES, "ck_alerts_severity"),
        _check("confidence", CONFIDENCES, "ck_alerts_confidence"),
        _check("status", ALERT_STATUSES, "ck_alerts_status"),
        CheckConstraint(
            "disposition IS NULL OR disposition IN ('true_positive','benign_positive','false_positive','undetermined')",
            name="ck_alerts_disposition",
        ),
        Index("ix_alerts_org_status_time", "org_id", "status", "last_seen"),
        Index("ix_alerts_org_rule", "org_id", "rule_id"),
        Index("ix_alerts_incident", "incident_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    rule_id: Mapped[str] = mapped_column(String(32), ForeignKey("detection_rules.id", ondelete="RESTRICT"), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    disposition: Mapped[str | None] = mapped_column(String(32))
    disposition_reason: Mapped[str | None] = mapped_column(Text)
    dedup_key: Mapped[str] = mapped_column(String(200), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    entities: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"))
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    rule: Mapped[DetectionRule] = relationship(lazy="raise")


class AlertEvent(Base):
    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True)


# --- incidents --------------------------------------------------------------


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("org_id", "number", name="uq_incidents_org_number"),
        _check("severity", SEVERITIES, "ck_incidents_severity"),
        _check("status", INCIDENT_STATUSES, "ck_incidents_status"),
        CheckConstraint(
            "verdict IS NULL OR verdict IN ('true_positive','benign_positive','false_positive','undetermined')",
            name="ck_incidents_verdict",
        ),
        # A closed incident must record why it was closed.
        CheckConstraint("status <> 'closed' OR (verdict IS NOT NULL AND closure_reason IS NOT NULL)", name="ck_incidents_closure"),
        Index("ix_incidents_org_status", "org_id", "status"),
        Index("ix_incidents_org_created", "org_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    verdict: Mapped[str | None] = mapped_column(String(32))
    closure_reason: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40), nullable=False, default="detection")
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Optimistic concurrency token: clients send it back on updates.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id], lazy="raise")


class IncidentEvent(Base):
    """An event explicitly linked to an incident as evidence."""

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    added_at: Mapped[datetime] = _created_at()
    reason: Mapped[str | None] = mapped_column(String(300))


class IncidentNote(Base):
    """Notes are append-only. Corrections are new notes, never edits."""

    __tablename__ = "incident_notes"
    __table_args__ = (
        _check("note_type", NOTE_TYPES, "ck_incident_notes_type"),
        Index("ix_incident_notes_incident", "incident_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    author_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    note_type: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()

    author: Mapped[User | None] = relationship(lazy="raise")


class Evidence(Base):
    """Immutable evidence record with provenance and a content hash."""

    __tablename__ = "evidence"
    __table_args__ = (
        _check("evidence_type", EVIDENCE_TYPES, "ck_evidence_type"),
        Index("ix_evidence_incident", "incident_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source_ref: Mapped[str | None] = mapped_column(String(120))
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = _created_at()


# --- threat intelligence ----------------------------------------------------


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("org_id", "ioc_type", "value", name="uq_indicators_org_type_value"),
        _check("ioc_type", IOC_TYPES, "ck_indicators_type"),
        CheckConstraint("analyst_verdict IN ('unknown','benign','suspicious','malicious')", name="ck_indicators_analyst_verdict"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    analyst_verdict: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    analyst_note: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = _created_at()
    last_looked_up: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lookup_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class IndicatorEnrichment(Base):
    __tablename__ = "indicator_enrichments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('ok','not_found','error','rate_limited','unconfigured','unsupported')",
            name="ck_indicator_enrichments_status",
        ),
        Index("ix_indicator_enrichments_lookup", "indicator_id", "provider", "fetched_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    indicator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # What the provider reported, mapped to a common vocabulary. Never inferred
    # from missing data: absence of a result stays "unknown".
    reported_verdict: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    fetched_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IndicatorLookup(Base):
    """Investigation history: who looked up what, and in which incident."""

    __tablename__ = "indicator_lookups"
    __table_args__ = (Index("ix_indicator_lookups_org_time", "org_id", "requested_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    indicator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"))
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    requested_at: Mapped[datetime] = _created_at()
    used_cache: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class IncidentIndicator(Base):
    __tablename__ = "incident_indicators"

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    indicator_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"), primary_key=True)
    added_at: Mapped[datetime] = _created_at()


# --- response ---------------------------------------------------------------


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    min_role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        UniqueConstraint("org_id", "idempotency_key", name="uq_playbook_runs_idempotency"),
        CheckConstraint("status IN ('completed','awaiting_approval','failed')", name="ck_playbook_runs_status"),
        Index("ix_playbook_runs_incident", "incident_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    playbook_id: Mapped[str] = mapped_column(String(64), ForeignKey("playbooks.id", ondelete="RESTRICT"), nullable=False)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)
    output: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = _created_at()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        _check("status", ACTION_STATUSES, "ck_response_actions_status"),
        UniqueConstraint("org_id", "idempotency_key", name="uq_response_actions_idempotency"),
        Index("ix_response_actions_org_status", "org_id", "status"),
        Index("ix_response_actions_incident", "incident_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID] = _org_fk()
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    playbook_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("playbook_runs.id", ondelete="SET NULL"))
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False)
    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    rollback_plan: Mapped[str | None] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (CheckConstraint("decision IN ('approved','rejected')", name="ck_approvals_decision"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    response_action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("response_actions.id", ondelete="CASCADE"), nullable=False, unique=True)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = _created_at()


# --- audit and platform -------------------------------------------------------


class AuditLog(Base):
    """Append-only. A database trigger rejects UPDATE and DELETE (see migration 0001)."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_org_time", "org_id", "created_at"),
        Index("ix_audit_logs_target", "target_type", "target_id"),
        Index("ix_audit_logs_action", "org_id", "action"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    org_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"))
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(320), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _created_at()


class RateLimitBucket(Base):
    """Fixed-window counters. Stored in Postgres because serverless instances share no memory."""

    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
