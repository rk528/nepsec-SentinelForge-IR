"""Audit search, users, data sources, ingestion, scenarios and system info."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app import audit, ratelimit
from app.audit import RequestContext
from app.config import get_settings
from app.connectors.fortigate import map_fortigate_payload
from app.connectors.linux import map_linux_payload
from app.connectors.microsoft import map_records
from app.db import get_db
from app.deps import Admin, Analyst, Lead, Principal, Viewer, get_ctx, request_context, require_non_demo
from app.detection.engine import run_detection
from app.intel.providers import PROVIDERS
from app.models import AuditLog, DataSource, Event, Organization, User
from app.schemas import AuditOut, DataSourceCreateIn, EventIn, IngestIn, IngestOut, Page, UserCreateIn, UserRef, UserUpdateIn
from app.security import hash_password, new_token, sha256_hex
from app.services import demo, mail, onboarding
from app.services.ingest import ingest_events
from app.services.scenarios import SCENARIOS, scenario_metadata

router = APIRouter(tags=["administration"])


# --- audit ---------------------------------------------------------------------


@router.get("/audit", response_model=Page[AuditOut])
def search_audit(
    principal: Principal = Lead,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    action: str | None = Query(None, max_length=80),
    actor: str | None = Query(None, max_length=320),
    target_type: str | None = Query(None, max_length=40),
    target_id: str | None = Query(None, max_length=80),
    start: datetime | None = None,
    end: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> Page[AuditOut]:
    stmt = select(AuditLog).where(AuditLog.org_id == principal.org_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(AuditLog.action.ilike(like), AuditLog.actor_label.ilike(like), AuditLog.target_id.ilike(like)))
    if action:
        stmt = stmt.where(AuditLog.action.like(action.replace("*", "%")))
    if actor:
        stmt = stmt.where(AuditLog.actor_label.ilike(f"%{actor}%"))
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if start:
        stmt = stmt.where(AuditLog.created_at >= start)
    if end:
        stmt = stmt.where(AuditLog.created_at <= end)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars()
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


# --- users -----------------------------------------------------------------------


@router.get("/users", response_model=list[UserRef])
def list_users(principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[UserRef]:
    rows = db.execute(select(User).where(User.org_id == principal.org_id, User.is_active.is_(True)).order_by(User.display_name)).scalars()
    return [UserRef.model_validate(u) for u in rows]


@router.get("/admin/users")
def admin_list_users(principal: Principal = Admin, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.execute(select(User).where(User.org_id == principal.org_id, User.removed_at.is_(None)).order_by(User.created_at)).scalars()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "display_name": u.display_name,
            "role": u.role,
            "is_active": u.is_active,
            "is_demo": u.is_demo,
            "created_at": u.created_at.isoformat(),
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "must_change_password": u.must_change_password,
        }
        for u in rows
    ]


def _delivery(db: Session, ctx: RequestContext, user: User, action: str, message: mail.Email, fallback: dict[str, str]) -> dict[str, Any]:
    """Send an onboarding/reset email after the account change is committed, and audit the outcome.

    When the email cannot be sent, the secrets are returned to the administrator
    once instead, so the account is never left unreachable.
    """
    result = mail.send_email(message)
    audit.record(
        db,
        ctx,
        f"{action}_emailed" if result.sent else f"{action}_email_failed",
        target_type="user",
        target_id=user.id,
        details={"to": user.email, "provider_id": result.provider_id} if result.sent else {"to": user.email, "reason": result.error},
    )
    db.commit()
    if result.sent:
        return {"email_sent": True, "email_error": None}
    return {"email_sent": False, "email_error": result.error, **fallback}


@router.post("/admin/users", status_code=201)
def create_user(
    body: UserCreateIn, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Create an account with a generated temporary password and email the user their onboarding details."""
    if db.execute(select(User.id).where(func.lower(User.email) == body.email.lower())).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    temp = onboarding.temporary_password()
    user = User(
        org_id=principal.org_id,
        email=body.email.lower(),
        display_name=body.display_name,
        role=body.role,
        password_hash=hash_password(temp),
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    token = onboarding.issue_token(db, user, "invite", principal.user_id)
    audit.record(db, ctx, "user.created", target_type="user", target_id=user.id, details={"email": user.email, "role": user.role})
    db.commit()
    db.refresh(user)

    link = onboarding.password_link(token)
    message = onboarding.invite_email(user, onboarding.system_facts(db, user), temp, link, f"{principal.display_name} ({principal.email})")
    return {"id": str(user.id), **_delivery(db, ctx, user, "user.invite", message, {"temporary_password": temp, "password_link": link})}


@router.post("/admin/users/{user_id}/send-reset")
def send_password_reset(
    user_id: uuid.UUID, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Email the user a one-time link to choose a new password. Their current password keeps working until it is used."""
    user = db.execute(select(User).where(User.id == user_id, User.org_id == principal.org_id, User.removed_at.is_(None))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_demo or not user.is_active:
        raise HTTPException(status_code=422, detail="Reactivate the account before sending a password reset")
    ratelimit.hit(db, f"reset-mail:user:{user.id}", 5, 3600)
    token = onboarding.issue_token(db, user, "reset", principal.user_id)
    audit.record(db, ctx, "user.password_reset_issued", target_type="user", target_id=user.id, details={"email": user.email})
    db.commit()

    link = onboarding.password_link(token)
    message = onboarding.reset_email(user, onboarding.system_facts(db, user), link, f"{principal.display_name} ({principal.email})")
    return _delivery(db, ctx, user, "user.password_reset", message, {"password_link": link})


@router.patch("/admin/users/{user_id}")
def update_user(
    user_id: uuid.UUID,
    body: UserUpdateIn,
    principal: Principal = Admin,
    _: Principal = Depends(require_non_demo),
    ctx: RequestContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    user = db.execute(select(User).where(User.id == user_id, User.org_id == principal.org_id, User.removed_at.is_(None))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == principal.user_id and (body.role not in (None, "admin") or body.is_active is False):
        raise HTTPException(status_code=422, detail="You cannot demote or deactivate yourself")
    changes = {}
    if body.role and body.role != user.role:
        changes["role"] = {"from": user.role, "to": body.role}
        user.role = body.role
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": body.is_active}
        user.is_active = body.is_active
        if not body.is_active:
            db.execute(text("UPDATE user_sessions SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL"), {"u": user.id})
    audit.record(db, ctx, "user.updated", target_type="user", target_id=user.id, details={"changes": changes})
    db.commit()
    return {"id": str(user.id), "role": user.role, "is_active": user.is_active}


@router.delete("/admin/users/{user_id}", status_code=204)
def remove_user(
    user_id: uuid.UUID, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> Response:
    """Remove an account: it can no longer sign in, disappears from user lists, and its email is freed.

    The row is kept (anonymised) because the audit log is append-only and incidents,
    notes and approvals keep pointing at who did what; the audit entry records the email.
    """
    user = db.execute(select(User).where(User.id == user_id, User.org_id == principal.org_id, User.removed_at.is_(None))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == principal.user_id:
        raise HTTPException(status_code=422, detail="You cannot remove your own account")
    if (
        user.role == "admin"
        and not db.execute(
            select(User.id).where(User.org_id == principal.org_id, User.role == "admin", User.is_active.is_(True), User.removed_at.is_(None), User.id != user.id).limit(1)
        ).first()
    ):
        raise HTTPException(status_code=422, detail="The organisation must keep at least one active administrator")
    email, name = user.email, user.display_name
    db.execute(text("UPDATE user_sessions SET revoked_at = now() WHERE user_id = :u AND revoked_at IS NULL"), {"u": user.id})
    user.is_active = False
    user.password_hash = None
    user.removed_at = datetime.now(UTC)
    user.email = f"removed-{user.id.hex}@removed.invalid"
    user.display_name = f"{name} (removed)"[:120]
    audit.record(db, ctx, "user.removed", target_type="user", target_id=user.id, details={"email": email, "display_name": name})
    db.commit()
    return Response(status_code=204)


# --- data sources and ingestion -------------------------------------------------------


def _source_dict(s: DataSource) -> dict[str, Any]:
    return {
        "id": str(s.id),
        "name": s.name,
        "source_type": s.source_type,
        "description": s.description,
        "is_enabled": s.is_enabled,
        "is_synthetic": s.is_synthetic,
        "event_count": s.event_count,
        "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
        "has_ingest_key": s.ingest_key_hash is not None,
        "ingest_key_prefix": s.ingest_key_prefix,
        "created_at": s.created_at.isoformat(),
    }


@router.get("/data-sources")
def list_sources(principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.execute(select(DataSource).where(DataSource.org_id == principal.org_id).order_by(DataSource.name)).scalars()
    return [_source_dict(s) for s in rows]


@router.post("/data-sources", status_code=201)
def create_source(
    body: DataSourceCreateIn, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    if db.execute(select(DataSource.id).where(DataSource.org_id == principal.org_id, DataSource.name == body.name)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A data source with that name already exists")
    key = "sfk_" + new_token(32)
    src = DataSource(
        org_id=principal.org_id, name=body.name, source_type=body.source_type, description=body.description, ingest_key_hash=sha256_hex(key), ingest_key_prefix=key[:10]
    )
    db.add(src)
    db.flush()
    audit.record(db, ctx, "data_source.created", target_type="data_source", target_id=src.id, details={"name": src.name, "type": src.source_type})
    db.commit()
    # The key is returned exactly once; only its hash is stored.
    return {**_source_dict(src), "ingest_key": key}


@router.post("/data-sources/{source_id}/rotate-key")
def rotate_key(
    source_id: uuid.UUID, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    src = db.execute(select(DataSource).where(DataSource.id == source_id, DataSource.org_id == principal.org_id)).scalar_one_or_none()
    if src is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    key = "sfk_" + new_token(32)
    src.ingest_key_hash, src.ingest_key_prefix = sha256_hex(key), key[:10]
    audit.record(db, ctx, "data_source.key_rotated", target_type="data_source", target_id=src.id)
    db.commit()
    return {**_source_dict(src), "ingest_key": key}


@router.post("/data-sources/{source_id}/revoke-key")
def revoke_key(
    source_id: uuid.UUID, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Invalidate the source's ingest key immediately. History is kept; rotate to issue a new key."""
    src = db.execute(select(DataSource).where(DataSource.id == source_id, DataSource.org_id == principal.org_id)).scalar_one_or_none()
    if src is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    src.ingest_key_hash = src.ingest_key_prefix = None
    audit.record(db, ctx, "data_source.key_revoked", target_type="data_source", target_id=src.id)
    db.commit()
    return _source_dict(src)


@router.delete("/data-sources/{source_id}", status_code=204)
def delete_source(
    source_id: uuid.UUID, principal: Principal = Admin, _: Principal = Depends(require_non_demo), ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)
) -> Response:
    """Delete a source that never received events. Sources with events keep their evidence; revoke the key instead."""
    src = db.execute(select(DataSource).where(DataSource.id == source_id, DataSource.org_id == principal.org_id)).scalar_one_or_none()
    if src is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    if db.execute(select(Event.id).where(Event.data_source_id == src.id).limit(1)).first():
        raise HTTPException(status_code=409, detail="This source has stored events that may be evidence. Revoke its key to stop ingestion instead.")
    audit.record(db, ctx, "data_source.deleted", target_type="data_source", target_id=src.id, details={"name": src.name})
    db.delete(src)
    db.commit()
    return Response(status_code=204)


@router.post("/ingest/events", response_model=IngestOut, tags=["ingestion"])
def ingest(body: IngestIn, request: Request, db: Session = Depends(get_db)) -> IngestOut:
    """Machine-to-machine ingestion, authenticated by a per-source key (``Authorization: Bearer sfk_...``).

    This endpoint is separate from the analyst API: it does not accept session cookies.
    """
    src = _ingest_source(request, db)
    return _ingest(request, db, src, body.events, run=body.run_detection)


MAX_VENDOR_RECORDS = 500


@router.post("/ingest/microsoft/{fmt}", response_model=IngestOut, tags=["ingestion"])
def ingest_microsoft(
    fmt: Literal["entra-signin", "entra-audit", "defender-alert", "windows-event"],
    request: Request,
    payload: Any = Body(...),
    db: Session = Depends(get_db),
    run_detection: bool = True,
) -> IngestOut:
    """Microsoft logs in their native JSON shape, mapped to normalised events.

    Accepts a Graph response (``{"value": [...]}``), an Azure Monitor export
    (``{"records": [...]}``), a JSON array, or a single record. Same ingest key as
    ``/ingest/events``. Records that do not map to a supported event are counted as skipped.
    """
    src = _ingest_source(request, db)
    events, skipped = map_records(fmt, payload)
    if len(events) + skipped > MAX_VENDOR_RECORDS:
        raise HTTPException(status_code=413, detail=f"At most {MAX_VENDOR_RECORDS} records per request")
    out = _ingest(request, db, src, events, run=run_detection, details={"format": fmt, "skipped": skipped})
    out.skipped = skipped
    return out


@router.post("/ingest/fortigate", response_model=IngestOut, tags=["ingestion"])
def ingest_fortigate(request: Request, payload: Any = Body(...), db: Session = Depends(get_db), run_detection: bool = True) -> IngestOut:
    """FortiGate logs as sent by the syslog relay: ``{"logs": [line, ...]}``.

    Lines may be FortiOS ``key=value`` or JSON, with or without a syslog header.
    Same ingest key as ``/ingest/events``; unmapped lines are counted as skipped.
    """
    src = _ingest_source(request, db)
    events, skipped = map_fortigate_payload(payload)
    if len(events) + skipped > MAX_VENDOR_RECORDS:
        raise HTTPException(status_code=413, detail=f"At most {MAX_VENDOR_RECORDS} records per request")
    out = _ingest(request, db, src, events, run=run_detection, details={"format": "fortigate", "skipped": skipped})
    out.skipped = skipped
    return out


@router.post("/ingest/linux", response_model=IngestOut, tags=["ingestion"])
def ingest_linux(request: Request, payload: Any = Body(...), db: Session = Depends(get_db), run_detection: bool = True) -> IngestOut:
    """Linux journal records as sent by the Linux shipper: ``{"records": [journalctl -o json objects]}``.

    Same ingest key as ``/ingest/events``; records that do not map are counted as skipped.
    """
    src = _ingest_source(request, db)
    events, skipped = map_linux_payload(payload)
    if len(events) + skipped > MAX_VENDOR_RECORDS:
        raise HTTPException(status_code=413, detail=f"At most {MAX_VENDOR_RECORDS} records per request")
    out = _ingest(request, db, src, events, run=run_detection, details={"format": "linux-journald", "skipped": skipped})
    out.skipped = skipped
    return out


def _ingest_source(request: Request, db: Session) -> DataSource:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not auth[7:].startswith("sfk_") or len(auth) > 200:
        raise HTTPException(status_code=401, detail="Missing or invalid ingest key", headers={"WWW-Authenticate": "Bearer"})
    src = db.execute(select(DataSource).where(DataSource.ingest_key_hash == sha256_hex(auth[7:].strip()))).scalar_one_or_none()
    if src is None or not src.is_enabled:
        raise HTTPException(status_code=401, detail="Missing or invalid ingest key", headers={"WWW-Authenticate": "Bearer"})
    s = get_settings()
    ratelimit.hit(db, f"ingest:{src.id}", s.ingest_rate_limit, s.ingest_rate_window_seconds)
    return src


def _ingest(request: Request, db: Session, src: DataSource, events: list[EventIn], *, run: bool, details: dict[str, Any] | None = None) -> IngestOut:
    result = ingest_events(db, src.org_id, src, events)
    ctx = RequestContext(org_id=src.org_id, user_id=None, actor_label=f"ingest:{src.name}", ip=request_context(request).ip, request_id=getattr(request.state, "request_id", None))
    created = updated = 0
    if run and result.inserted and result.earliest:
        summary = run_detection(db, src.org_id, since=result.earliest, ctx=ctx)
        created, updated = summary.alerts_created, summary.alerts_updated
    audit.record(db, ctx, "ingest.batch", target_type="data_source", target_id=src.id, details={"received": result.received, "inserted": result.inserted, **(details or {})})
    db.commit()
    return IngestOut(received=result.received, inserted=result.inserted, duplicates=result.received - result.inserted, alerts_created=created, alerts_updated=updated)


# --- scenarios ------------------------------------------------------------------------


@router.get("/scenarios")
def list_scenarios(principal: Principal = Viewer) -> list[dict[str, Any]]:
    return scenario_metadata()


@router.post("/scenarios/{scenario_id}/run")
def run_scenario(scenario_id: str, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found")
    org = db.get(Organization, principal.org_id)
    # Synthetic data is only injected into demo workspaces, or by an admin who explicitly chooses to.
    if not (org and org.is_demo) and not principal.can("admin"):
        raise HTTPException(status_code=403, detail="Scenarios can only be run in a demo workspace or by an admin")
    ratelimit.hit(db, f"scenario:{principal.org_id}", 20, 3600)
    # Start slightly in the past so correlation windows complete before "now".
    start = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=30)
    result = demo.run_scenario(db, ctx, principal.org_id, scenario_id, start, variant=f"-{new_token(3).lower()}")
    db.commit()
    return result


# --- settings / system ------------------------------------------------------------------


@router.get("/system")
def system_info(principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    s = get_settings()
    try:
        revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
    except Exception:  # noqa: BLE001
        db.rollback()
        revision = None
    org = db.get(Organization, principal.org_id)
    return {
        "version": s.app_version,
        "environment": s.app_env,
        "demo_mode": s.demo_mode,
        "migration_revision": revision,
        "organization": {"name": org.name if org else None, "is_demo": bool(org and org.is_demo)},
        "integrations": [{"name": p.label, "configured": p.configured()} for p in PROVIDERS],
        "email": {"provider": "Resend", "configured": mail.mail_configured(), "sender": s.mail_from},
        "session": {"ttl_hours": s.session_ttl_hours, "idle_minutes": s.session_idle_minutes},
        "limits": {
            "max_body_bytes": s.max_body_bytes,
            "max_ingest_body_bytes": s.max_ingest_body_bytes,
            "login_rate_limit": f"{s.login_rate_limit}/{s.login_rate_window_seconds}s",
        },
    }
