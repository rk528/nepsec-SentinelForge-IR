from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import case, false, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.db import get_db
from app.deps import Analyst, Principal, Viewer, get_ctx
from app.models import (
    Alert,
    AuditLog,
    DetectionRule,
    Event,
    Evidence,
    Incident,
    IncidentEvent,
    IncidentNote,
    ResponseAction,
    User,
)
from app.schemas import (
    AlertOut,
    AuditOut,
    EventOut,
    EvidenceOut,
    IncidentCreateIn,
    IncidentOut,
    IncidentTransitionIn,
    IncidentUpdateIn,
    LinkEventsIn,
    NoteIn,
    NoteOut,
    Page,
    UserRef,
)
from app.services import incidents as svc
from app.services import reports

router = APIRouter(prefix="/incidents", tags=["incidents"])

SORTS = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "number": Incident.number,
    "severity": case({"critical": 4, "high": 3, "medium": 2, "low": 1}, value=Incident.severity, else_=0),
}


def to_out(i: Incident, assignee: User | None, alert_count: int = 0, event_count: int = 0) -> IncidentOut:
    return IncidentOut(
        id=i.id,
        number=i.number,
        reference=svc.reference(i.number),
        title=i.title,
        summary=i.summary,
        severity=i.severity,
        status=i.status,
        verdict=i.verdict,
        closure_reason=i.closure_reason,  # type: ignore[arg-type]
        source=i.source,
        tags=list(i.tags or []),
        assignee=UserRef.model_validate(assignee) if assignee else None,
        is_synthetic=i.is_synthetic,
        created_at=i.created_at,
        updated_at=i.updated_at,
        acknowledged_at=i.acknowledged_at,
        contained_at=i.contained_at,
        resolved_at=i.resolved_at,
        closed_at=i.closed_at,
        version=i.version,
        alert_count=alert_count,
        event_count=event_count,
    )


def _org_user(db: Session, principal: Principal, user_id: uuid.UUID) -> User:
    user = db.execute(select(User).where(User.id == user_id, User.org_id == principal.org_id, User.is_active.is_(True))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=422, detail="Assignee must be an active user in your organisation")
    return user


@router.get("", response_model=Page[IncidentOut])
def list_incidents(
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    status: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    assignee_id: uuid.UUID | None = None,
    unassigned: bool = False,
    source: str | None = Query(None, max_length=40),
    tag: str | None = Query(None, max_length=64),
    sort: Literal["created_at", "updated_at", "number", "severity"] = "created_at",
    order: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Page[IncidentOut]:
    stmt = select(Incident).where(Incident.org_id == principal.org_id)
    if q:
        like = f"%{q.strip()}%"
        num = q.strip().upper().removeprefix("INC-")
        conds = [Incident.title.ilike(like), Incident.summary.ilike(like)]
        if num.isdigit():
            conds.append(Incident.number == int(num))
        stmt = stmt.where(or_(*conds))
    if status:
        stmt = stmt.where(Incident.status.in_(status))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity))
    if assignee_id:
        stmt = stmt.where(Incident.assignee_id == assignee_id)
    if unassigned:
        stmt = stmt.where(Incident.assignee_id.is_(None))
    if source:
        stmt = stmt.where(Incident.source == source)
    if tag:
        stmt = stmt.where(Incident.tags.any(tag.lower()))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    col = SORTS[sort]
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc(), Incident.number.desc())
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars().all()

    ids = [r.id for r in rows]
    alert_counts, event_counts = svc.counts_for(db, ids)
    assignee_ids = {r.assignee_id for r in rows if r.assignee_id}
    users = {u.id: u for u in db.execute(select(User).where(User.id.in_(assignee_ids))).scalars()} if assignee_ids else {}
    items = [to_out(r, users.get(r.assignee_id) if r.assignee_id else None, alert_counts.get(r.id, 0), event_counts.get(r.id, 0)) for r in rows]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(body: IncidentCreateIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> IncidentOut:
    alerts: list[Alert] = []
    if body.alert_ids:
        alerts = list(db.execute(select(Alert).where(Alert.id.in_(body.alert_ids), Alert.org_id == principal.org_id)).scalars())
        if len(alerts) != len(set(body.alert_ids)):
            raise HTTPException(status_code=404, detail="One or more alerts were not found")
    inc = svc.create_incident(
        db,
        ctx,
        principal.org_id,
        title=body.title,
        summary=body.summary,
        severity=body.severity,
        tags=body.tags,
        source="manual",
        created_by=principal.user_id,
        alerts=alerts,
    )
    db.commit()
    return to_out(inc, None, len(alerts))


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> IncidentOut:
    inc = svc.get_incident(db, principal, incident_id)
    ac, ec = svc.counts_for(db, [inc.id])
    assignee = db.get(User, inc.assignee_id) if inc.assignee_id else None
    return to_out(inc, assignee, ac.get(inc.id, 0), ec.get(inc.id, 0))


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID, body: IncidentUpdateIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> IncidentOut:
    inc = svc.get_incident(db, principal, incident_id, lock=True)
    svc.check_version(inc, body.version)
    if inc.status == "closed":
        raise HTTPException(status_code=409, detail="Closed incidents are read-only; reopen first")
    changes: dict[str, Any] = {}
    for field in ("title", "summary", "severity", "tags"):
        value = getattr(body, field)
        if value is not None and value != getattr(inc, field):
            changes[field] = {"from": getattr(inc, field), "to": value}
            setattr(inc, field, value)
    if body.clear_assignee and inc.assignee_id is not None:
        changes["assignee_id"] = {"from": str(inc.assignee_id), "to": None}
        inc.assignee_id = None
    elif body.assignee_id and body.assignee_id != inc.assignee_id:
        _org_user(db, principal, body.assignee_id)
        changes["assignee_id"] = {"from": str(inc.assignee_id) if inc.assignee_id else None, "to": str(body.assignee_id)}
        inc.assignee_id = body.assignee_id
    if changes:
        svc.touch(inc)
        audit.record(db, ctx, "incident.updated", target_type="incident", target_id=inc.id, details={"changes": changes})
        db.commit()
    return get_incident(incident_id, principal, db)


@router.post("/{incident_id}/transition", response_model=IncidentOut)
def transition(
    incident_id: uuid.UUID, body: IncidentTransitionIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> IncidentOut:
    inc = svc.get_incident(db, principal, incident_id, lock=True)
    svc.check_version(inc, body.version)
    svc.transition(db, ctx, principal, inc, body.status, verdict=body.verdict, closure_reason=body.closure_reason, reason=body.reason)
    db.commit()
    return get_incident(incident_id, principal, db)


@router.get("/{incident_id}/notes", response_model=list[NoteOut])
def list_notes(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[NoteOut]:
    svc.get_incident(db, principal, incident_id)
    rows = db.execute(
        select(IncidentNote, User).outerjoin(User, User.id == IncidentNote.author_id).where(IncidentNote.incident_id == incident_id).order_by(IncidentNote.created_at)
    ).all()
    return [NoteOut(id=n.id, note_type=n.note_type, body=n.body, created_at=n.created_at, author=UserRef.model_validate(u) if u else None) for n, u in rows]


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(incident_id: uuid.UUID, body: NoteIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> NoteOut:
    inc = svc.get_incident(db, principal, incident_id, lock=True)
    if inc.status == "closed":
        raise HTTPException(status_code=409, detail="Closed incidents are read-only; reopen first")
    note = IncidentNote(org_id=principal.org_id, incident_id=inc.id, author_id=principal.user_id, note_type=body.note_type, body=body.body.strip())
    db.add(note)
    svc.touch(inc)
    db.flush()
    audit.record(db, ctx, "incident.note_added", target_type="incident", target_id=inc.id, details={"note_id": str(note.id), "note_type": body.note_type, "length": len(body.body)})
    db.commit()
    author = db.get(User, principal.user_id)
    return NoteOut(id=note.id, note_type=note.note_type, body=note.body, created_at=note.created_at, author=UserRef.model_validate(author))


@router.get("/{incident_id}/events", response_model=list[EventOut])
def incident_events(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[EventOut]:
    svc.get_incident(db, principal, incident_id)
    rows = (
        db.execute(
            select(Event)
            .join(IncidentEvent, IncidentEvent.event_id == Event.id)
            .where(IncidentEvent.incident_id == incident_id, Event.org_id == principal.org_id)
            .order_by(Event.event_time)
        )
        .scalars()
        .all()
    )
    show_raw = principal.can("analyst")
    return [EventOut.model_validate(e).model_copy(update={"raw": e.raw if show_raw else None}) for e in rows]


@router.post("/{incident_id}/events", status_code=201)
def link_events(
    incident_id: uuid.UUID, body: LinkEventsIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, int]:
    inc = svc.get_incident(db, principal, incident_id, lock=True)
    if inc.status == "closed":
        raise HTTPException(status_code=409, detail="Closed incidents are read-only; reopen first")
    ids = set(body.event_ids)
    found = set(db.execute(select(Event.id).where(Event.id.in_(ids), Event.org_id == principal.org_id)).scalars())
    if found != ids:
        raise HTTPException(status_code=404, detail="One or more events were not found")
    result = (
        db.execute(
            pg_insert(IncidentEvent)
            .values([{"incident_id": inc.id, "event_id": e, "added_by": principal.user_id, "reason": body.reason or "Linked by analyst"} for e in ids])
            .on_conflict_do_nothing()
            .returning(IncidentEvent.event_id)
        )
        .scalars()
        .all()
    )
    if result:
        svc.touch(inc)
        audit.record(db, ctx, "incident.events_linked", target_type="incident", target_id=inc.id, details={"event_ids": [str(e) for e in result], "reason": body.reason})
    db.commit()
    return {"linked": len(result)}


@router.get("/{incident_id}/alerts", response_model=list[AlertOut])
def incident_alerts(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[AlertOut]:
    inc = svc.get_incident(db, principal, incident_id)
    rows = db.execute(
        select(Alert, DetectionRule.name)
        .join(DetectionRule, DetectionRule.id == Alert.rule_id)
        .where(Alert.incident_id == inc.id, Alert.org_id == principal.org_id)
        .order_by(Alert.first_seen)
    ).all()
    return [AlertOut.model_validate(a).model_copy(update={"rule_name": n, "incident_number": inc.number}) for a, n in rows]


@router.get("/{incident_id}/evidence", response_model=list[EvidenceOut])
def incident_evidence(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[EvidenceOut]:
    svc.get_incident(db, principal, incident_id)
    rows = db.execute(select(Evidence).where(Evidence.incident_id == incident_id, Evidence.org_id == principal.org_id).order_by(Evidence.created_at)).scalars().all()
    return [EvidenceOut.model_validate(e) for e in rows]


@router.get("/{incident_id}/timeline")
def incident_timeline(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    inc = svc.get_incident(db, principal, incident_id)
    return svc.build_timeline(db, inc)


@router.get("/{incident_id}/audit", response_model=list[AuditOut])
def incident_audit(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[AuditOut]:
    inc = svc.get_incident(db, principal, incident_id)
    action_ids = [str(a) for a in db.execute(select(ResponseAction.id).where(ResponseAction.incident_id == inc.id)).scalars()]
    rows = (
        db.execute(
            select(AuditLog)
            .where(
                AuditLog.org_id == principal.org_id,
                or_(
                    (AuditLog.target_type == "incident") & (AuditLog.target_id == str(inc.id)),
                    (AuditLog.target_type == "response_action") & (AuditLog.target_id.in_(action_ids)) if action_ids else false(),
                ),
            )
            .order_by(AuditLog.created_at.desc())
            .limit(200)
        )
        .scalars()
        .all()
    )
    return [AuditOut.model_validate(a) for a in rows]


@router.get("/{incident_id}/report", response_model=None)
def incident_report(
    incident_id: uuid.UUID,
    request: Request,
    format: Literal["json", "markdown"] = "json",
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
) -> Any:
    inc = svc.get_incident(db, principal, incident_id)
    report = reports.build_report(db, inc)
    if format == "markdown":
        filename = f"{svc.reference(inc.number)}-report.md"
        return PlainTextResponse(
            reports.render_markdown(report),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    return report
