from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.db import get_db
from app.deps import Analyst, Principal, Viewer, get_ctx
from app.detection.engine import sync_rule_metadata
from app.detection.rules import MANUAL_RULE, RULES_BY_ID
from app.models import Alert, AlertEvent, DataSource, DetectionRule, Event, Incident, IncidentEvent, User
from app.schemas import AlertCreateIn, AlertEscalateIn, AlertOut, AlertTriageIn, EventOut, LinkEventsIn, Page
from app.services import incidents as inc_svc

router = APIRouter(prefix="/alerts", tags=["alerts"])

SEV_ORDER = case({"critical": 4, "high": 3, "medium": 2, "low": 1}, value=Alert.severity, else_=0)


def _get_alert(db: Session, principal: Principal, alert_id: uuid.UUID, *, lock: bool = False) -> Alert:
    stmt = select(Alert).where(Alert.id == alert_id, Alert.org_id == principal.org_id)
    if lock:
        stmt = stmt.with_for_update()
    alert = db.execute(stmt).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _out(db: Session, alerts: list[Alert]) -> list[AlertOut]:
    rule_names = dict(db.execute(select(DetectionRule.id, DetectionRule.name)).all())
    inc_ids = {a.incident_id for a in alerts if a.incident_id}
    numbers = dict(db.execute(select(Incident.id, Incident.number).where(Incident.id.in_(inc_ids))).all()) if inc_ids else {}
    return [AlertOut.model_validate(a).model_copy(update={"rule_name": rule_names.get(a.rule_id), "incident_number": numbers.get(a.incident_id)}) for a in alerts]


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    status: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    rule_id: list[str] = Query(default=[]),
    hours: int | None = Query(None, ge=1, le=24 * 90),
    escalated: bool | None = None,
    sort: Literal["last_seen", "first_seen", "severity", "occurrence_count"] = "last_seen",
    order: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Page[AlertOut]:
    stmt = select(Alert).where(Alert.org_id == principal.org_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Alert.title.ilike(like), Alert.description.ilike(like), Alert.rule_id.ilike(like)))
    if status:
        stmt = stmt.where(Alert.status.in_(status))
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity))
    if rule_id:
        stmt = stmt.where(Alert.rule_id.in_(rule_id))
    if hours:
        stmt = stmt.where(Alert.last_seen >= datetime.now(UTC) - timedelta(hours=hours))
    if escalated is True:
        stmt = stmt.where(Alert.incident_id.is_not(None))
    elif escalated is False:
        stmt = stmt.where(Alert.incident_id.is_(None))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    col = {"last_seen": Alert.last_seen, "first_seen": Alert.first_seen, "severity": SEV_ORDER, "occurrence_count": Alert.occurrence_count}[sort]
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc(), Alert.last_seen.desc())
    rows = list(db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page(items=_out(db, rows), total=total, page=page, page_size=page_size)


def _org_events(db: Session, principal: Principal, ids: set[uuid.UUID]) -> list[Event]:
    found = list(db.execute(select(Event).where(Event.id.in_(ids), Event.org_id == principal.org_id)).scalars())
    if len(found) != len(ids):
        raise HTTPException(status_code=404, detail="One or more events were not found")
    return found


def _add_events(db: Session, principal: Principal, alert: Alert, events: list[Event], reason: str) -> list[uuid.UUID]:
    """Link events to an alert, and to its incident when it has one. Returns the events that were not linked before."""
    added = list(
        db.execute(pg_insert(AlertEvent).values([{"alert_id": alert.id, "event_id": e.id} for e in events]).on_conflict_do_nothing().returning(AlertEvent.event_id)).scalars()
    )
    if added and alert.incident_id:
        db.execute(
            pg_insert(IncidentEvent)
            .values([{"incident_id": alert.incident_id, "event_id": e, "added_by": principal.user_id, "reason": reason[:300]} for e in added])
            .on_conflict_do_nothing()
        )
    if added:
        times = [e.event_time for e in events if e.id in set(added)]
        alert.first_seen = min([alert.first_seen, *times])
        alert.last_seen = max([alert.last_seen, *times])
        alert.updated_at = datetime.now(UTC)
    return added


@router.post("", response_model=AlertOut, status_code=201)
def create_alert(body: AlertCreateIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> AlertOut:
    """Raise an alert by hand, from events an analyst picked or from something no rule covers."""
    events = _org_events(db, principal, set(body.event_ids)) if body.event_ids else []
    incident = inc_svc.get_incident(db, principal, body.incident_id, lock=True) if body.incident_id else None
    if incident is not None and incident.status == "closed":
        raise HTTPException(status_code=409, detail="Cannot link to a closed incident")
    sync_rule_metadata(db)  # the hand-raised rule's row must exist before an alert can name it
    now = datetime.now(UTC)
    times = sorted(e.event_time for e in events) or [now]
    first = events[0] if events else None
    entities = {k: v for k, v in {"host": first.host if first else None, "user": first.user_name if first else None, "src_ip": first.src_ip if first else None}.items() if v}
    user = db.get(User, principal.user_id)
    alert = Alert(
        org_id=principal.org_id,
        rule_id=MANUAL_RULE.id,
        title=body.title,
        description=body.description or "Raised by hand; no description was given.",
        severity=body.severity,
        confidence=MANUAL_RULE.confidence,
        status="new",
        dedup_key=f"{MANUAL_RULE.id}:{uuid.uuid4()}",
        occurrence_count=max(len(events), 1),
        first_seen=times[0],
        last_seen=times[-1],
        entities=entities,
        evidence_summary={"raised_by": user.display_name if user else "an analyst", "method": "manual"},
    )
    db.add(alert)
    db.flush()
    if events:
        _add_events(db, principal, alert, events, "Picked when the alert was raised")
    audit.record(db, ctx, "alert.created", target_type="alert", target_id=alert.id, details={"rule_id": MANUAL_RULE.id, "manual": True, "event_count": len(events)})
    if incident is not None:
        inc_svc.link_alert(db, ctx, incident, alert)
    db.commit()
    return _out(db, [alert])[0]


@router.post("/{alert_id}/events", status_code=201)
def link_events(alert_id: uuid.UUID, body: LinkEventsIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, int]:
    """Link more events to an alert as its evidence. They go to its incident as well, when it has one."""
    alert = _get_alert(db, principal, alert_id, lock=True)
    events = _org_events(db, principal, set(body.event_ids))
    added = _add_events(db, principal, alert, events, body.reason or f"Linked to alert {alert.title[:200]}")
    if added:
        audit.record(db, ctx, "alert.events_linked", target_type="alert", target_id=alert.id, details={"event_ids": [str(e) for e in added], "reason": body.reason})
    db.commit()
    return {"linked": len(added)}


@router.delete("/{alert_id}/incident")
def unlink_incident(alert_id: uuid.UUID, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> AlertOut:
    """Take an alert out of its incident. It goes back to acknowledged; the incident keeps what was copied into it as evidence."""
    alert = _get_alert(db, principal, alert_id, lock=True)
    if alert.incident_id is None:
        raise HTTPException(status_code=409, detail="This alert is not linked to an incident")
    incident = inc_svc.get_incident(db, principal, alert.incident_id, lock=True)
    if incident.status == "closed":
        raise HTTPException(status_code=409, detail="Closed incidents are read-only; reopen first")
    alert.incident_id = None
    alert.status = "acknowledged"
    alert.updated_at = datetime.now(UTC)
    inc_svc.touch(incident)
    audit.record(db, ctx, "incident.alert_unlinked", target_type="incident", target_id=incident.id, details={"alert_id": str(alert.id)})
    db.commit()
    return _out(db, [alert])[0]


@router.get("/{alert_id}")
def get_alert(alert_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = _get_alert(db, principal, alert_id)
    events = db.execute(
        select(Event, DataSource.name)
        .join(AlertEvent, AlertEvent.event_id == Event.id)
        .join(DataSource, DataSource.id == Event.data_source_id)
        .where(AlertEvent.alert_id == alert.id, Event.org_id == principal.org_id)
        .order_by(Event.event_time)
    ).all()
    show_raw = principal.can("analyst")
    rule = RULES_BY_ID.get(alert.rule_id)
    db_rule = db.get(DetectionRule, alert.rule_id)
    assignee = db.get(User, alert.assignee_id) if alert.assignee_id else None
    return {
        "alert": _out(db, [alert])[0],
        "rule": {**(rule.metadata() if rule else {}), "enabled": db_rule.enabled if db_rule else None},
        "events": [EventOut.model_validate(e).model_copy(update={"raw": e.raw if show_raw else None, "data_source_name": name}) for e, name in events],
        "assignee": {"id": str(assignee.id), "display_name": assignee.display_name} if assignee else None,
    }


@router.patch("/{alert_id}", response_model=AlertOut)
def triage_alert(alert_id: uuid.UUID, body: AlertTriageIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> AlertOut:
    alert = _get_alert(db, principal, alert_id, lock=True)
    changes: dict[str, Any] = {}
    if body.status and body.status != alert.status:
        if body.status == "escalated":
            raise HTTPException(status_code=422, detail="Use the escalate endpoint to link an alert to an incident")
        changes["status"] = {"from": alert.status, "to": body.status}
        alert.status = body.status
    if body.disposition and body.disposition != alert.disposition:
        changes["disposition"] = {"from": alert.disposition, "to": body.disposition}
        alert.disposition = body.disposition
        alert.disposition_reason = body.disposition_reason
    if body.assignee_id and body.assignee_id != alert.assignee_id:
        ok = db.execute(select(User.id).where(User.id == body.assignee_id, User.org_id == principal.org_id, User.is_active.is_(True))).scalar_one_or_none()
        if ok is None:
            raise HTTPException(status_code=422, detail="Assignee must be an active user in your organisation")
        changes["assignee_id"] = {"from": str(alert.assignee_id) if alert.assignee_id else None, "to": str(body.assignee_id)}
        alert.assignee_id = body.assignee_id
    if changes:
        alert.updated_at = datetime.now(UTC)
        audit.record(db, ctx, "alert.triaged", target_type="alert", target_id=alert.id, details={"changes": changes, "reason": body.disposition_reason})
        db.commit()
    return _out(db, [alert])[0]


@router.post("/{alert_id}/escalate")
def escalate(alert_id: uuid.UUID, body: AlertEscalateIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Link the alert to an existing incident, or open a new one from it."""
    alert = _get_alert(db, principal, alert_id, lock=True)
    if body.incident_id:
        incident = inc_svc.get_incident(db, principal, body.incident_id, lock=True)
        if incident.status == "closed":
            raise HTTPException(status_code=409, detail="Cannot link to a closed incident")
        inc_svc.link_alert(db, ctx, incident, alert)
        created = False
    else:
        if alert.incident_id:
            raise HTTPException(status_code=409, detail="Alert is already linked to an incident")
        incident = inc_svc.create_incident(
            db,
            ctx,
            principal.org_id,
            title=(body.title or alert.title)[:300],
            summary=alert.description,
            severity=alert.severity,
            tags=[alert.rule_id.lower()],
            source="detection",
            created_by=principal.user_id,
            alerts=[alert],
        )
        created = True
    audit.record(db, ctx, "alert.escalated", target_type="alert", target_id=alert.id, details={"incident_id": str(incident.id), "created_incident": created})
    db.commit()
    return {"incident_id": str(incident.id), "reference": inc_svc.reference(incident.number), "created": created}
