"""Run playbooks and handle the approval workflow for gated actions."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.deps import Principal
from app.models import Approval, Incident, PlaybookRun, ResponseAction
from app.playbooks.registry import PLAYBOOKS, sync_playbooks, validate_block_targets
from app.services import incidents as inc_svc

log = logging.getLogger(__name__)


def run_playbook(
    db: Session,
    ctx: RequestContext,
    principal: Principal,
    playbook_id: str,
    incident: Incident,
    idempotency_key: str,
    params: dict[str, Any],
) -> tuple[PlaybookRun, bool]:
    """Returns (run, created). Re-using an idempotency key returns the original run."""
    spec = PLAYBOOKS.get(playbook_id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not principal.can(spec.min_role):
        raise HTTPException(status_code=403, detail=f"Requires {spec.min_role} role or higher")
    if incident.status == "closed" and playbook_id != "closure_report":
        raise HTTPException(status_code=409, detail="Incident is closed; reopen it before running response playbooks")

    existing = db.execute(select(PlaybookRun).where(PlaybookRun.org_id == incident.org_id, PlaybookRun.idempotency_key == idempotency_key)).scalar_one_or_none()
    if existing is not None:
        if existing.playbook_id != playbook_id or existing.incident_id != incident.id:
            raise HTTPException(status_code=409, detail="Idempotency key already used for a different request")
        return existing, False

    sync_playbooks(db)
    run = PlaybookRun(
        org_id=incident.org_id,
        playbook_id=playbook_id,
        incident_id=incident.id,
        requested_by=principal.user_id,
        status="completed",
        idempotency_key=idempotency_key,
    )
    db.add(run)
    db.flush()

    action = ResponseAction(
        org_id=incident.org_id,
        incident_id=incident.id,
        playbook_run_id=run.id,
        action_type=playbook_id,
        parameters=params,
        requested_by=principal.user_id,
        requires_approval=spec.requires_approval,
        simulated=spec.simulated,
        rollback_plan=spec.rollback_plan,
        idempotency_key=f"{idempotency_key}:action",
        status="pending_approval",
    )

    if spec.requires_approval:
        # Validate now so an approver never sees an unexecutable request.
        action.parameters = {**params, "ip_addresses": validate_block_targets(params)}
        run.status = "awaiting_approval"
        run.output = {"message": "Awaiting approval from a lead who did not request it."}
        db.add(action)
    else:
        nested = db.begin_nested()
        try:
            output = spec.handler(db, ctx, incident, params)
            nested.commit()
            run.output = output
            action.status = "executed"
            action.result = output
            action.executed_at = datetime.now(UTC)
        except HTTPException:
            nested.rollback()
            raise
        except Exception as exc:  # recorded, not swallowed: the run is marked failed
            nested.rollback()
            log.exception("playbook %s failed", playbook_id)
            run.status = "failed"
            run.error = f"{type(exc).__name__}: playbook step failed"
            action.status = "failed"
            action.error = run.error
        run.completed_at = datetime.now(UTC)
        db.add(action)

    inc_svc.touch(incident)
    audit.record(
        db,
        ctx,
        "playbook.run",
        target_type="incident",
        target_id=incident.id,
        details={"playbook_id": playbook_id, "run_id": str(run.id), "status": run.status, "idempotency_key": idempotency_key},
    )
    db.flush()
    return run, True


def get_action(db: Session, principal: Principal, action_id: uuid.UUID, *, lock: bool = False) -> ResponseAction:
    stmt = select(ResponseAction).where(ResponseAction.id == action_id, ResponseAction.org_id == principal.org_id)
    if lock:
        stmt = stmt.with_for_update()
    action = db.execute(stmt).scalar_one_or_none()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    return action


def decide(db: Session, ctx: RequestContext, principal: Principal, action_id: uuid.UUID, decision: str, reason: str) -> ResponseAction:
    if not principal.can("lead"):
        raise HTTPException(status_code=403, detail="Approving response actions requires the lead role")
    action = get_action(db, principal, action_id, lock=True)
    if action.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Action is {action.status}, not pending approval")
    # Separation of duties: the requester can never approve their own action.
    if action.requested_by == principal.user_id:
        raise HTTPException(status_code=403, detail="You cannot approve or reject an action you requested")

    db.add(Approval(response_action_id=action.id, decided_by=principal.user_id, decision=decision, reason=reason))
    now = datetime.now(UTC)
    audit.record(
        db,
        ctx,
        f"response_action.{decision}",
        target_type="response_action",
        target_id=action.id,
        details={"action_type": action.action_type, "reason": reason, "requested_by": str(action.requested_by)},
    )

    run = db.get(PlaybookRun, action.playbook_run_id) if action.playbook_run_id else None
    if decision == "rejected":
        action.status = "rejected"
        if run:
            run.status = "completed"
            run.output = {"message": "Rejected by approver", "reason": reason}
            run.completed_at = now
    else:
        incident = db.get(Incident, action.incident_id)
        assert incident is not None
        spec = PLAYBOOKS[action.action_type]
        try:
            result = spec.handler(db, ctx, incident, action.parameters)
            action.status = "executed"
            action.result = result
            action.executed_at = now
            inc_svc.add_evidence(
                db,
                incident,
                evidence_type="playbook_output",
                title=f"Simulated execution: {spec.name}",
                content={"action_id": str(action.id), **result},
                provenance={"method": f"playbook:{spec.id}", "simulated": True, "approved_by": principal.email},
                collected_by=principal.user_id,
            )
            audit.record(db, ctx, "response_action.executed", target_type="response_action", target_id=action.id, details={"simulated": True})
        except HTTPException as exc:
            action.status = "failed"
            action.error = str(exc.detail)
        if run:
            run.status = "completed" if action.status == "executed" else "failed"
            run.output = action.result or {"error": action.error}
            run.completed_at = now
        inc_svc.touch(incident)
    action.updated_at = now
    return action


def cancel(db: Session, ctx: RequestContext, principal: Principal, action_id: uuid.UUID) -> ResponseAction:
    action = get_action(db, principal, action_id, lock=True)
    if action.status != "pending_approval":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending actions can be cancelled")
    if action.requested_by != principal.user_id and not principal.can("lead"):
        raise HTTPException(status_code=403, detail="Only the requester or a lead can cancel this action")
    action.status = "cancelled"
    action.updated_at = datetime.now(UTC)
    if action.playbook_run_id:
        run = db.get(PlaybookRun, action.playbook_run_id)
        if run:
            run.status = "completed"
            run.output = {"message": "Cancelled before approval"}
            run.completed_at = action.updated_at
    audit.record(db, ctx, "response_action.cancelled", target_type="response_action", target_id=action.id)
    return action
