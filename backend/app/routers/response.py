from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import RequestContext
from app.db import get_db
from app.deps import Analyst, Principal, Viewer, get_ctx
from app.models import Approval, Incident, PlaybookRun, ResponseAction, User
from app.playbooks import service as pb
from app.playbooks.registry import PLAYBOOKS
from app.schemas import ApprovalIn, Page, PlaybookRunIn, ResponseActionOut
from app.services import incidents as inc_svc

router = APIRouter(tags=["response"])


@router.get("/playbooks")
def list_playbooks(principal: Principal = Viewer) -> list[dict[str, Any]]:
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "category": p.category,
            "requires_approval": p.requires_approval,
            "min_role": p.min_role,
            "simulated": p.simulated,
            "rollback_plan": p.rollback_plan,
        }
        for p in PLAYBOOKS.values()
    ]


@router.post("/playbooks/{playbook_id}/run")
def run_playbook(
    playbook_id: str, body: PlaybookRunIn, response: Response, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    incident = inc_svc.get_incident(db, principal, body.incident_id, lock=True)
    run, created = pb.run_playbook(db, ctx, principal, playbook_id, incident, body.idempotency_key, body.parameters)
    db.commit()
    response.status_code = 201 if created else 200
    return {
        "id": str(run.id),
        "playbook_id": run.playbook_id,
        "status": run.status,
        "output": run.output,
        "error": run.error,
        "idempotent_replay": not created,
    }


@router.get("/playbooks/runs")
def list_runs(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    inc_svc.get_incident(db, principal, incident_id)
    rows = db.execute(
        select(PlaybookRun, User.display_name)
        .outerjoin(User, User.id == PlaybookRun.requested_by)
        .where(PlaybookRun.incident_id == incident_id, PlaybookRun.org_id == principal.org_id)
        .order_by(PlaybookRun.started_at.desc())
    ).all()
    return [
        {
            "id": str(r.id),
            "playbook_id": r.playbook_id,
            "status": r.status,
            "requested_by": name,
            "started_at": r.started_at.isoformat(),
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "output": r.output,
            "error": r.error,
        }
        for r, name in rows
    ]


def _actions_out(db: Session, actions: list[ResponseAction]) -> list[ResponseActionOut]:
    user_ids = {a.requested_by for a in actions if a.requested_by}
    approvals = {ap.response_action_id: ap for ap in db.execute(select(Approval).where(Approval.response_action_id.in_([a.id for a in actions]))).scalars()} if actions else {}
    user_ids |= {ap.decided_by for ap in approvals.values() if ap.decided_by}
    names = dict(db.execute(select(User.id, User.display_name).where(User.id.in_(user_ids))).all()) if user_ids else {}
    numbers = dict(db.execute(select(Incident.id, Incident.number).where(Incident.id.in_({a.incident_id for a in actions}))).all()) if actions else {}
    out = []
    for a in actions:
        ap = approvals.get(a.id)
        out.append(
            ResponseActionOut.model_validate(a).model_copy(
                update={
                    "incident_number": numbers.get(a.incident_id),
                    "requested_by_name": names.get(a.requested_by),
                    "approval": {"decision": ap.decision, "reason": ap.reason, "decided_by": names.get(ap.decided_by), "decided_at": ap.decided_at.isoformat()} if ap else None,
                }
            )
        )
    return out


@router.get("/response-actions", response_model=Page[ResponseActionOut])
def list_actions(
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    status: list[str] = Query(default=[]),
    incident_id: uuid.UUID | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Page[ResponseActionOut]:
    stmt = select(ResponseAction).where(ResponseAction.org_id == principal.org_id)
    if status:
        stmt = stmt.where(ResponseAction.status.in_(status))
    if incident_id:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(db.execute(stmt.order_by(ResponseAction.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page(items=_actions_out(db, rows), total=total, page=page, page_size=page_size)


@router.post("/response-actions/{action_id}/decision", response_model=ResponseActionOut)
def decide(action_id: uuid.UUID, body: ApprovalIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> ResponseActionOut:
    action = pb.decide(db, ctx, principal, action_id, body.decision, body.reason)
    db.commit()
    return _actions_out(db, [action])[0]


@router.post("/response-actions/{action_id}/cancel", response_model=ResponseActionOut)
def cancel(action_id: uuid.UUID, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> ResponseActionOut:
    action = pb.cancel(db, ctx, principal, action_id)
    db.commit()
    return _actions_out(db, [action])[0]
