from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import Principal, Viewer
from app.models import Alert, AlertEvent, DataSource, Event, Incident, IncidentEvent
from app.schemas import EVENT_TYPES, EventOut, Page

router = APIRouter(prefix="/events", tags=["events"])


def _serialise(principal: Principal, rows: list[tuple[Event, str]]) -> list[EventOut]:
    show_raw = principal.can("analyst")
    return [EventOut.model_validate(e).model_copy(update={"raw": e.raw if show_raw else None, "data_source_name": n}) for e, n in rows]


@router.get("", response_model=Page[EventOut])
def search_events(
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200, description="Free text across host, user, IPs, domain, process and command line"),
    event_type: list[str] = Query(default=[]),
    host: str | None = Query(None, max_length=255),
    user: str | None = Query(None, max_length=255),
    ip: str | None = Query(None, max_length=64, description="Matches source or destination"),
    domain: str | None = Query(None, max_length=255),
    data_source_id: uuid.UUID | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    hours: int | None = Query(None, ge=1, le=24 * 90),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> Page[EventOut]:
    stmt = select(Event, DataSource.name).join(DataSource, DataSource.id == Event.data_source_id).where(Event.org_id == principal.org_id)
    if event_type:
        invalid = set(event_type) - set(EVENT_TYPES)
        if invalid:
            raise HTTPException(status_code=422, detail=f"Unknown event type(s): {', '.join(sorted(invalid))}")
        stmt = stmt.where(Event.event_type.in_(event_type))
    if host:
        stmt = stmt.where(Event.host == host)
    if user:
        stmt = stmt.where(or_(Event.user_name == user, Event.target_user == user))
    if ip:
        stmt = stmt.where(or_(Event.src_ip == ip, Event.dst_ip == ip))
    if domain:
        stmt = stmt.where(Event.domain == domain.lower())
    if data_source_id:
        stmt = stmt.where(Event.data_source_id == data_source_id)
    if hours:
        stmt = stmt.where(Event.event_time >= datetime.now(UTC) - timedelta(hours=hours))
    if start:
        stmt = stmt.where(Event.event_time >= start)
    if end:
        stmt = stmt.where(Event.event_time <= end)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Event.host.ilike(like),
                Event.user_name.ilike(like),
                Event.src_ip.ilike(like),
                Event.dst_ip.ilike(like),
                Event.domain.ilike(like),
                Event.process_name.ilike(like),
                Event.command_line.ilike(like),
                Event.target_user.ilike(like),
            )
        )
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Event.event_time.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=_serialise(principal, [(e, n) for e, n in rows]), total=total, page=page, page_size=page_size)


@router.get("/{event_id}")
def get_event(event_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = db.execute(select(Event, DataSource).join(DataSource, DataSource.id == Event.data_source_id).where(Event.id == event_id, Event.org_id == principal.org_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found")
    event, source = row
    alerts = db.execute(
        select(Alert.id, Alert.title, Alert.severity, Alert.rule_id)
        .join(AlertEvent, AlertEvent.alert_id == Alert.id)
        .where(AlertEvent.event_id == event.id, Alert.org_id == principal.org_id)
    ).all()
    incidents = db.execute(
        select(Incident.id, Incident.number, Incident.title, IncidentEvent.reason)
        .join(IncidentEvent, IncidentEvent.incident_id == Incident.id)
        .where(IncidentEvent.event_id == event.id, Incident.org_id == principal.org_id)
    ).all()
    return {
        "event": _serialise(principal, [(event, source.name)])[0],
        "provenance": {
            "data_source": {"id": str(source.id), "name": source.name, "type": source.source_type, "synthetic": source.is_synthetic},
            "ingested_at": event.ingested_at.isoformat(),
            "fingerprint": event.fingerprint,
            "scenario_id": event.scenario_id,
        },
        "alerts": [{"id": str(i), "title": t, "severity": s, "rule_id": r} for i, t, s, r in alerts],
        "incidents": [{"id": str(i), "reference": f"INC-{n:04d}", "title": t, "link_reason": reason} for i, n, t, reason in incidents],
    }


@router.get("/{event_id}/related", response_model=list[EventOut])
def related_events(
    event_id: uuid.UUID,
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    window_minutes: int = Query(60, ge=1, le=24 * 60),
) -> list[EventOut]:
    """Events sharing a host, user or IP within ±window of the given event."""
    event = db.execute(select(Event).where(Event.id == event_id, Event.org_id == principal.org_id)).scalar_one_or_none()
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    conds = []
    if event.host:
        conds.append(Event.host == event.host)
    if event.user_name:
        conds.append(Event.user_name == event.user_name)
    for ip in {event.src_ip, event.dst_ip} - {None}:
        conds.append(or_(Event.src_ip == ip, Event.dst_ip == ip))
    if not conds:
        return []
    w = timedelta(minutes=window_minutes)
    rows = db.execute(
        select(Event, DataSource.name)
        .join(DataSource, DataSource.id == Event.data_source_id)
        .where(Event.org_id == principal.org_id, Event.id != event.id, Event.event_time.between(event.event_time - w, event.event_time + w), or_(*conds))
        .order_by(Event.event_time)
        .limit(100)
    ).all()
    return _serialise(principal, [(e, n) for e, n in rows])
