"""Incident lifecycle, evidence handling and timeline assembly."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.deps import Principal
from app.models import (
    Alert,
    AlertEvent,
    AuditLog,
    Event,
    Evidence,
    Incident,
    IncidentEvent,
    IncidentNote,
    Organization,
    ResponseAction,
    User,
)

# Allowed lifecycle transitions. Reopening a closed incident is a separate,
# privileged operation (lead+) and always requires a reason.
TRANSITIONS: dict[str, set[str]] = {
    "new": {"open", "investigating", "closed"},
    "open": {"investigating", "closed"},
    "investigating": {"contained", "resolved", "closed"},
    "contained": {"investigating", "resolved"},
    "resolved": {"investigating", "closed"},
    "closed": set(),
}
REOPEN_TARGET = "open"

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def reference(number: int) -> str:
    return f"INC-{number:04d}"


def get_incident(db: Session, principal: Principal, incident_id: uuid.UUID, *, lock: bool = False) -> Incident:
    """Fetch an incident in the caller's organisation, or 404.

    Returning 404 (not 403) for other tenants' IDs avoids confirming that the
    record exists.
    """
    stmt = select(Incident).where(Incident.id == incident_id, Incident.org_id == principal.org_id)
    if lock:
        stmt = stmt.with_for_update()
    incident = db.execute(stmt).scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def next_incident_number(db: Session, org_id: uuid.UUID) -> int:
    return db.execute(update(Organization).where(Organization.id == org_id).values(incident_seq=Organization.incident_seq + 1).returning(Organization.incident_seq)).scalar_one()


def create_incident(
    db: Session,
    ctx: RequestContext,
    org_id: uuid.UUID,
    *,
    title: str,
    summary: str,
    severity: str,
    tags: list[str],
    source: str,
    created_by: uuid.UUID | None,
    alerts: list[Alert] | None = None,
    is_synthetic: bool = False,
) -> Incident:
    incident = Incident(
        org_id=org_id,
        number=next_incident_number(db, org_id),
        title=title,
        summary=summary,
        severity=severity,
        status="new",
        source=source,
        tags=tags,
        created_by=created_by,
        is_synthetic=is_synthetic,
    )
    db.add(incident)
    db.flush()
    audit.record(
        db,
        ctx,
        "incident.created",
        target_type="incident",
        target_id=incident.id,
        details={"reference": reference(incident.number), "severity": severity, "source": source},
        org_id=org_id,
    )
    for alert in alerts or []:
        link_alert(db, ctx, incident, alert)
    return incident


def link_alert(db: Session, ctx: RequestContext, incident: Incident, alert: Alert) -> None:
    if alert.org_id != incident.org_id:  # defence in depth; callers already scope by org
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.incident_id == incident.id:
        return
    previous = alert.incident_id
    alert.incident_id = incident.id
    alert.status = "escalated"
    alert.updated_at = datetime.now(UTC)
    # Promote the incident's severity if the alert is more severe.
    if SEVERITY_RANK[alert.severity] > SEVERITY_RANK[incident.severity]:
        incident.severity = alert.severity
    event_ids = db.execute(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id)).scalars().all()
    if event_ids:
        db.execute(
            pg_insert(IncidentEvent)
            .values([{"incident_id": incident.id, "event_id": eid, "added_by": ctx.user_id, "reason": f"Supporting event for alert {alert.rule_id}"} for eid in event_ids])
            .on_conflict_do_nothing()
        )
    add_evidence(
        db,
        incident,
        evidence_type="alert",
        title=f"Alert: {alert.title}",
        description=alert.description,
        source_ref=str(alert.id),
        content={
            "alert_id": str(alert.id),
            "rule_id": alert.rule_id,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "entities": alert.entities,
            "evidence_summary": alert.evidence_summary,
            "event_ids": [str(e) for e in event_ids],
        },
        provenance={"method": "detection_engine", "source_system": "SentinelForge detection engine", "rule_id": alert.rule_id},
        collected_by=ctx.user_id,
    )
    audit.record(
        db,
        ctx,
        "incident.alert_linked",
        target_type="incident",
        target_id=incident.id,
        details={"alert_id": str(alert.id), "previous_incident_id": str(previous) if previous else None},
        org_id=incident.org_id,
    )
    touch(incident)


def touch(incident: Incident) -> None:
    incident.updated_at = datetime.now(UTC)
    incident.version += 1


def check_version(incident: Incident, version: int) -> None:
    if incident.version != version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The incident was changed by someone else. Reload and try again.",
        )


def transition(
    db: Session,
    ctx: RequestContext,
    principal: Principal,
    incident: Incident,
    target: str,
    *,
    verdict: str | None,
    closure_reason: str | None,
    reason: str | None,
) -> None:
    current = incident.status
    if target == current:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Incident is already {current}")

    reopening = current == "closed"
    if reopening:
        if target != REOPEN_TARGET:
            raise HTTPException(status_code=422, detail="A closed incident can only be reopened to 'open'")
        if not principal.can("lead"):
            raise HTTPException(status_code=403, detail="Reopening a closed incident requires the lead role")
        if not reason or len(reason.strip()) < 5:
            raise HTTPException(status_code=422, detail="Reopening requires a reason")
    elif target not in TRANSITIONS[current]:
        allowed = ", ".join(sorted(TRANSITIONS[current])) or "none"
        raise HTTPException(status_code=422, detail=f"Cannot move from {current} to {target}. Allowed: {allowed}")

    if target == "closed":
        if not verdict or not closure_reason or len(closure_reason.strip()) < 5:
            raise HTTPException(status_code=422, detail="Closing requires a verdict and a closure reason")
        pending = db.execute(
            select(func.count()).select_from(ResponseAction).where(ResponseAction.incident_id == incident.id, ResponseAction.status.in_(("pending_approval", "approved")))
        ).scalar_one()
        if pending:
            raise HTTPException(status_code=409, detail=f"{pending} response action(s) are still pending; resolve them before closing")

    now = datetime.now(UTC)
    if current == "new" and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    if target == "contained" and incident.contained_at is None:
        incident.contained_at = now
    if target == "resolved":
        incident.resolved_at = now
    if target == "closed":
        incident.closed_at = now
        incident.verdict = verdict
        incident.closure_reason = closure_reason.strip() if closure_reason else None
        if incident.resolved_at is None:
            incident.resolved_at = now
    if reopening:
        incident.closed_at = None
        incident.resolved_at = None
        incident.verdict = None
        incident.closure_reason = None
    elif verdict and target != "closed":
        incident.verdict = verdict

    incident.status = target
    touch(incident)
    db.add(
        IncidentNote(
            org_id=incident.org_id,
            incident_id=incident.id,
            author_id=principal.user_id,
            note_type="system",
            body=f"Status changed from {current} to {target}." + (f" Reason: {reason.strip()}" if reason else ""),
        )
    )
    audit.record(
        db,
        ctx,
        "incident.reopened" if reopening else "incident.status_changed",
        target_type="incident",
        target_id=incident.id,
        details={"from": current, "to": target, "verdict": verdict, "closure_reason": closure_reason, "reason": reason},
    )


def canonical_sha256(content: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(content, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def add_evidence(
    db: Session,
    incident: Incident,
    *,
    evidence_type: str,
    title: str,
    content: dict[str, Any],
    provenance: dict[str, Any],
    description: str | None = None,
    source_ref: str | None = None,
    collected_by: uuid.UUID | None = None,
) -> Evidence:
    provenance = {"collected_at": datetime.now(UTC).isoformat(), **provenance}
    ev = Evidence(
        org_id=incident.org_id,
        incident_id=incident.id,
        evidence_type=evidence_type,
        title=title[:300],
        description=description,
        source_ref=source_ref,
        provenance=provenance,
        content=content,
        sha256=canonical_sha256(content),
        collected_by=collected_by,
    )
    db.add(ev)
    return ev


def counts_for(db: Session, incident_ids: list[uuid.UUID]) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, int]]:
    if not incident_ids:
        return {}, {}
    alert_counts = dict(db.execute(select(Alert.incident_id, func.count()).where(Alert.incident_id.in_(incident_ids)).group_by(Alert.incident_id)).all())
    event_counts = dict(db.execute(select(IncidentEvent.incident_id, func.count()).where(IncidentEvent.incident_id.in_(incident_ids)).group_by(IncidentEvent.incident_id)).all())
    return alert_counts, event_counts


def build_timeline(db: Session, incident: Incident) -> list[dict[str, Any]]:
    """Merge evidence events, alerts, notes, actions and audit records in time order."""
    items: list[dict[str, Any]] = []

    events = (
        db.execute(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(IncidentEvent.incident_id == incident.id).order_by(Event.event_time)).scalars().all()
    )
    for e in events:
        subject = e.user_name or e.target_user or e.src_ip or ""
        items.append(
            {
                "at": e.event_time,
                "kind": "event",
                "title": f"{e.event_type} on {e.host or e.src_ip or 'unknown'}",
                "detail": " · ".join(x for x in (subject, e.process_name, e.domain, e.dst_ip) if x) or None,
                "ref_id": str(e.id),
            }
        )

    for a in db.execute(select(Alert).where(Alert.incident_id == incident.id)).scalars():
        items.append({"at": a.first_seen, "kind": "alert", "title": a.title, "detail": a.rule_id, "ref_id": str(a.id), "severity": a.severity})

    notes = db.execute(select(IncidentNote, User.display_name).outerjoin(User, User.id == IncidentNote.author_id).where(IncidentNote.incident_id == incident.id)).all()
    for n, author in notes:
        items.append(
            {
                "at": n.created_at,
                "kind": "status" if n.note_type == "system" else "note",
                "title": n.body if n.note_type == "system" else ("Assessment added" if n.note_type == "assessment" else "Note added"),
                "detail": None if n.note_type == "system" else n.body[:280],
                "ref_id": str(n.id),
                "actor": author,
            }
        )

    for act in db.execute(select(ResponseAction).where(ResponseAction.incident_id == incident.id)).scalars():
        items.append(
            {
                "at": act.executed_at or act.updated_at,
                "kind": "action",
                "title": f"{act.action_type.replace('_', ' ')}: {act.status.replace('_', ' ')}",
                "detail": "Simulated action" if act.simulated else None,
                "ref_id": str(act.id),
            }
        )

    created = db.execute(
        select(AuditLog).where(AuditLog.target_type == "incident", AuditLog.target_id == str(incident.id), AuditLog.action == "incident.created")
    ).scalar_one_or_none()
    if created:
        items.append({"at": created.created_at, "kind": "audit", "title": "Incident opened", "actor": created.actor_label, "ref_id": str(created.id)})

    items.sort(key=lambda i: i["at"])
    return items
