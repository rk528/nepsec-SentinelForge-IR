"""Organisation-defined playbooks: ordered built-in actions and manual tasks, suggested by rule.

Automated steps run through the same service as the built-in playbooks, so role checks,
the closed-incident guard, idempotency and second-person approval all still apply.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.db import get_db
from app.deps import Analyst, Lead, Principal, Viewer, get_ctx
from app.detection.rules import RULES_BY_ID
from app.models import Alert, CustomPlaybook, CustomPlaybookRun, ResponseAction, User
from app.playbooks import service as pb
from app.playbooks.registry import PLAYBOOKS
from app.schemas import CustomPlaybookIn, CustomPlaybookPatch, CustomPlaybookStartIn, CustomStepUpdateIn, PlaybookStepIn
from app.services import incidents as inc_svc

router = APIRouter(tags=["response"])

FINISHED = {"done", "skipped"}


def _steps(steps: list[PlaybookStepIn]) -> list[dict[str, Any]]:
    out = []
    for i, s in enumerate(steps, 1):
        if s.kind == "action":
            if s.action not in PLAYBOOKS:
                raise HTTPException(status_code=422, detail=f"Step {i}: unknown automated action {str(s.action)[:64]!r}")
            out.append({"kind": "action", "action": s.action, "title": s.title, "instructions": s.instructions or None})
        else:
            out.append({"kind": "task", "action": None, "title": s.title, "instructions": s.instructions or None})
    return out


def _rules(rule_ids: list[str]) -> list[str]:
    unknown = [r for r in rule_ids if r not in RULES_BY_ID]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown detection rule: {unknown[0][:32]}")
    return sorted(set(rule_ids))


def _get(db: Session, principal: Principal, playbook_id: uuid.UUID) -> CustomPlaybook:
    p = db.execute(select(CustomPlaybook).where(CustomPlaybook.id == playbook_id, CustomPlaybook.org_id == principal.org_id)).scalar_one_or_none()
    if p is None or p.archived_at is not None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return p


def _out(p: CustomPlaybook, names: dict[uuid.UUID, str], suggested: bool = False) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "steps": p.steps,
        "trigger_rules": p.trigger_rules,
        "created_by": names.get(p.created_by) if p.created_by else None,
        "updated_at": p.updated_at.isoformat(),
        "suggested": suggested,
    }


def _names(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.display_name).where(User.id.in_(ids))).all()) if ids else {}


@router.get("/custom-playbooks")
def list_custom(principal: Principal = Viewer, db: Session = Depends(get_db), incident_id: uuid.UUID | None = None) -> list[dict[str, Any]]:
    rows = list(db.execute(select(CustomPlaybook).where(CustomPlaybook.org_id == principal.org_id, CustomPlaybook.archived_at.is_(None)).order_by(CustomPlaybook.name)).scalars())
    fired: set[str] = set()
    if incident_id:
        inc_svc.get_incident(db, principal, incident_id)
        fired = set(db.execute(select(Alert.rule_id).where(Alert.incident_id == incident_id, Alert.org_id == principal.org_id)).scalars())
    names = _names(db, {p.created_by for p in rows})
    out = [_out(p, names, bool(fired & set(p.trigger_rules))) for p in rows]
    return sorted(out, key=lambda x: not x["suggested"])


@router.post("/custom-playbooks", status_code=201)
def create_custom(body: CustomPlaybookIn, principal: Principal = Lead, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, Any]:
    p = CustomPlaybook(
        org_id=principal.org_id,
        name=body.name,
        description=body.description,
        steps=_steps(body.steps),
        trigger_rules=_rules(body.trigger_rules),
        created_by=principal.user_id,
        updated_by=principal.user_id,
    )
    db.add(p)
    db.flush()
    audit.record(db, ctx, "custom_playbook.created", target_type="custom_playbook", target_id=p.id, details={"name": p.name, "steps": len(p.steps)})
    db.commit()
    return _out(p, _names(db, {p.created_by}))


@router.patch("/custom-playbooks/{playbook_id}")
def update_custom(
    playbook_id: uuid.UUID, body: CustomPlaybookPatch, principal: Principal = Lead, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    p = _get(db, principal, playbook_id)
    changed = sorted(body.model_fields_set)
    if body.name is not None:
        p.name = body.name
    if body.description is not None:
        p.description = body.description
    if body.steps is not None:
        p.steps = _steps(body.steps)  # runs already started keep their own snapshot
    if body.trigger_rules is not None:
        p.trigger_rules = _rules(body.trigger_rules)
    p.updated_by = principal.user_id
    p.updated_at = datetime.now(UTC)
    audit.record(db, ctx, "custom_playbook.updated", target_type="custom_playbook", target_id=p.id, details={"fields": changed})
    db.commit()
    return _out(p, _names(db, {p.created_by}))


@router.delete("/custom-playbooks/{playbook_id}", status_code=204)
def archive_custom(playbook_id: uuid.UUID, principal: Principal = Lead, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> Response:
    p = _get(db, principal, playbook_id)
    p.archived_at = datetime.now(UTC)  # archived, not deleted: past runs still reference it
    audit.record(db, ctx, "custom_playbook.archived", target_type="custom_playbook", target_id=p.id, details={"name": p.name})
    db.commit()
    return Response(status_code=204)


@router.post("/custom-playbooks/{playbook_id}/start", status_code=201)
def start_custom(
    playbook_id: uuid.UUID, body: CustomPlaybookStartIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    p = _get(db, principal, playbook_id)
    incident = inc_svc.get_incident(db, principal, body.incident_id, lock=True)
    if incident.status == "closed":
        raise HTTPException(status_code=409, detail="Incident is closed; reopen it before starting a playbook")
    run = CustomPlaybookRun(
        org_id=principal.org_id,
        playbook_id=p.id,
        incident_id=incident.id,
        started_by=principal.user_id,
        status="in_progress",
        name=p.name,
        steps=[{**s, "status": "pending", "note": None, "by": None, "at": None, "playbook_run_id": None, "attempts": 0} for s in p.steps],
    )
    db.add(run)
    db.flush()
    inc_svc.touch(incident)
    audit.record(db, ctx, "custom_playbook.started", target_type="incident", target_id=incident.id, details={"playbook": p.name, "run_id": str(run.id)})
    db.commit()
    return _run_out(db, run)


def _sync(db: Session, run: CustomPlaybookRun) -> bool:
    """Carry approval decisions on gated steps into the run. Returns whether anything changed."""
    steps = [dict(s) for s in run.steps]
    changed = False
    for s in steps:
        if s["status"] != "awaiting_approval" or not s.get("playbook_run_id"):
            continue
        action = db.execute(select(ResponseAction).where(ResponseAction.playbook_run_id == uuid.UUID(s["playbook_run_id"]))).scalar_one_or_none()
        if action is None or action.status == "pending_approval":
            continue
        s["status"] = {"executed": "done", "failed": "failed"}.get(action.status, "skipped")
        if action.status in ("rejected", "cancelled"):
            s["note"] = f"Action {action.status} before execution"
        s["at"] = (action.executed_at or action.updated_at or datetime.now(UTC)).isoformat()
        changed = True
    if changed:
        run.steps = steps
        _finish(run)
    return changed


def _finish(run: CustomPlaybookRun) -> None:
    done = all(s["status"] in FINISHED for s in run.steps)
    run.status = "completed" if done else "in_progress"
    run.completed_at = run.completed_at or datetime.now(UTC) if done else None


def _run_out(db: Session, run: CustomPlaybookRun) -> dict[str, Any]:
    names = _names(db, {run.started_by})
    return {
        "id": str(run.id),
        "playbook_id": str(run.playbook_id),
        "incident_id": str(run.incident_id),
        "name": run.name,
        "status": run.status,
        "started_by": names.get(run.started_by) if run.started_by else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "steps": run.steps,
    }


@router.get("/custom-playbook-runs")
def list_runs(incident_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    inc_svc.get_incident(db, principal, incident_id)
    runs = list(
        db.execute(
            select(CustomPlaybookRun)
            .where(CustomPlaybookRun.incident_id == incident_id, CustomPlaybookRun.org_id == principal.org_id)
            .order_by(CustomPlaybookRun.started_at.desc())
        ).scalars()
    )
    if any([_sync(db, r) for r in runs]):
        db.commit()
    return [_run_out(db, r) for r in runs]


@router.post("/custom-playbook-runs/{run_id}/steps/{index}")
def update_step(
    run_id: uuid.UUID, index: int, body: CustomStepUpdateIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    run = db.execute(select(CustomPlaybookRun).where(CustomPlaybookRun.id == run_id, CustomPlaybookRun.org_id == principal.org_id).with_for_update()).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    incident = inc_svc.get_incident(db, principal, run.incident_id, lock=True)
    _sync(db, run)
    steps = [dict(s) for s in run.steps]
    if not 0 <= index < len(steps):
        raise HTTPException(status_code=404, detail="Step not found")
    step = steps[index]
    now = datetime.now(UTC).isoformat()

    if body.action == "reopen":
        if step["status"] == "awaiting_approval":
            raise HTTPException(status_code=409, detail="The step is waiting for an approval decision")
        step.update(status="pending", note=None, by=None, at=None)
    elif step["status"] in FINISHED or step["status"] == "awaiting_approval":
        raise HTTPException(status_code=409, detail=f"Step is already {step['status'].replace('_', ' ')}")
    elif body.action == "run":
        if step["kind"] != "action":
            raise HTTPException(status_code=422, detail="Only automated steps can be run; complete manual tasks instead")
        step["attempts"] = int(step.get("attempts") or 0) + 1
        result, _ = pb.run_playbook(db, ctx, principal, step["action"], incident, f"cpb:{run.id}:{index}:{step['attempts']}", body.parameters)
        step.update(
            status={"completed": "done", "awaiting_approval": "awaiting_approval"}.get(result.status, "failed"),
            playbook_run_id=str(result.id),
            note=result.error or body.note or None,
            by=principal.display_name,
            at=now,
        )
    else:
        if body.action == "complete" and step["kind"] == "action":
            raise HTTPException(status_code=422, detail="Run the automated step, or skip it with a reason")
        if body.action == "skip" and len(body.note) < 3:
            raise HTTPException(status_code=422, detail="Give a reason (at least 3 characters) for skipping a step")
        step.update(status="done" if body.action == "complete" else "skipped", note=body.note or None, by=principal.display_name, at=now)
        if body.action == "complete" and body.note:
            inc_svc.add_evidence(
                db,
                incident,
                evidence_type="analyst_observation",
                title=f"{run.name}: {step['title']}"[:500],
                content={"note": body.note, "step": index + 1, "playbook": run.name},
                provenance={"method": "custom_playbook:task", "run_id": str(run.id)},
                collected_by=principal.user_id,
            )

    run.steps = steps
    _finish(run)
    inc_svc.touch(incident)
    audit.record(
        db,
        ctx,
        f"custom_playbook.step_{body.action}",
        target_type="incident",
        target_id=incident.id,
        details={"run_id": str(run.id), "step": index + 1, "title": step["title"], "status": step["status"]},
    )
    db.commit()
    return _run_out(db, run)
