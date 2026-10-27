from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit, ratelimit
from app.config import get_settings
from app.db import get_db
from app.deps import Principal, client_ip, get_principal, request_context
from app.models import Organization, User, UserSession
from app.schemas import DemoLoginIn, LoginIn, MeOut
from app.security import new_token, sha256_hex, verify_password
from app.services.demo import DEMO_SLUG

router = APIRouter(prefix="/auth", tags=["auth"])


def _start_session(db: Session, request: Request, response: Response, user: User) -> str:
    settings = get_settings()
    token, csrf = new_token(), new_token()
    now = datetime.now(UTC)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=sha256_hex(token),
            csrf_hash=sha256_hex(csrf),
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
            last_seen_at=now,
            ip=client_ip(request),
            user_agent=(request.headers.get("user-agent") or "")[:400],
        )
    )
    user.last_login_at = now
    max_age = settings.session_ttl_hours * 3600
    response.set_cookie(settings.session_cookie_name, token, max_age=max_age, httponly=True, secure=settings.cookie_secure, samesite="lax", path="/")
    # Readable by the SPA so it can echo the value in X-CSRF-Token.
    response.set_cookie(settings.csrf_cookie_name, csrf, max_age=max_age, httponly=False, secure=settings.cookie_secure, samesite="lax", path="/")
    return csrf


def _me(user: User, org: Organization, csrf: str | None = None) -> MeOut:
    return MeOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,  # type: ignore[arg-type]
        org_id=org.id,
        org_name=org.name,
        is_demo=user.is_demo,
        csrf_token=csrf,
    )


@router.get("/config")
def auth_config() -> dict[str, bool]:
    """Public: tells the login page whether demo sign-in is offered."""
    return {"demo_mode": get_settings().demo_mode}


@router.post("/login", response_model=MeOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> MeOut:
    settings = get_settings()
    ip = client_ip(request) or "unknown"
    ratelimit.hit(db, f"login:ip:{ip}", settings.login_rate_limit * 3, settings.login_rate_window_seconds)
    ratelimit.hit(db, f"login:acct:{body.email.lower()}", settings.login_rate_limit, settings.login_rate_window_seconds)

    user = db.execute(select(User).where(func.lower(User.email) == body.email.lower())).scalar_one_or_none()
    ok = verify_password(body.password, user.password_hash if user else None)
    ctx = request_context(request)
    if not ok or user is None or not user.is_active or user.is_demo:
        audit.record(db, ctx, "auth.login_failed", target_type="user", details={"email": body.email.lower()}, org_id=user.org_id if user else None)
        db.commit()
        # Same message whether the account exists or not.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    csrf = _start_session(db, request, response, user)
    ctx.org_id, ctx.user_id, ctx.actor_label = user.org_id, user.id, user.email
    audit.record(db, ctx, "auth.login", target_type="user", target_id=user.id)
    db.commit()
    return _me(user, user.organization, csrf)


@router.post("/demo", response_model=MeOut)
def demo_login(body: DemoLoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> MeOut:
    settings = get_settings()
    if not settings.demo_mode:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    ratelimit.hit(db, f"demo:ip:{client_ip(request) or 'unknown'}", 30, 300)
    user = db.execute(
        select(User)
        .join(Organization, Organization.id == User.org_id)
        .where(Organization.slug == DEMO_SLUG, Organization.is_demo.is_(True), User.is_demo.is_(True), User.role == body.role, User.is_active.is_(True))
        .order_by(User.email)
        .limit(1)
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Demo workspace is not seeded")
    csrf = _start_session(db, request, response, user)
    ctx = request_context(request)
    ctx.org_id, ctx.user_id, ctx.actor_label = user.org_id, user.id, user.email
    audit.record(db, ctx, "auth.demo_login", target_type="user", target_id=user.id, details={"role": body.role})
    db.commit()
    return _me(user, user.organization, csrf)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Response:
    settings = get_settings()
    db.execute(update(UserSession).where(UserSession.id == principal.session_id).values(revoked_at=datetime.now(UTC)))
    audit.record(db, request_context(request, principal), "auth.logout", target_type="user", target_id=principal.user_id)
    db.commit()
    response = Response(status_code=204)
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
    return response


@router.post("/logout-all", status_code=204)
def logout_all(request: Request, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Response:
    """Revoke every session for the current user (e.g. after a suspected compromise)."""
    settings = get_settings()
    db.execute(update(UserSession).where(UserSession.user_id == principal.user_id, UserSession.revoked_at.is_(None)).values(revoked_at=datetime.now(UTC)))
    audit.record(db, request_context(request, principal), "auth.logout_all", target_type="user", target_id=principal.user_id)
    db.commit()
    response = Response(status_code=204)
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")
    return response


@router.get("/me", response_model=MeOut)
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> MeOut:
    user = db.get(User, principal.user_id)
    assert user is not None
    return _me(user, user.organization)
