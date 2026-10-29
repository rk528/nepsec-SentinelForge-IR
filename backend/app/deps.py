"""Request dependencies: authentication, CSRF, role checks and audit context.

Identity is always derived from the server-side session row looked up by the
hashed session cookie. Nothing the browser sends in a body or query string is
trusted to identify the user or their organisation.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import RequestContext
from app.config import get_settings
from app.db import get_db
from app.models import User, UserSession
from app.security import constant_time_equals, role_at_least, sha256_hex
from app.services import console_gate

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# The only endpoints a user signed in with a temporary password may call.
PASSWORD_CHANGE_ALLOWED = {"/api/v1/auth/me", "/api/v1/auth/password", "/api/v1/auth/logout", "/api/v1/auth/logout-all"}


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    display_name: str
    role: str
    is_demo: bool
    session_id: uuid.UUID

    def can(self, minimum_role: str) -> bool:
        return role_at_least(self.role, minimum_role)


def client_ip(request: Request) -> str | None:
    if get_settings().trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()[:64]
    return request.client.host if request.client else None


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    return _principal(request, db, get_settings().session_cookie_name)


def get_console_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    """The administrator signed in to the admin console. The app's own session cookie does not count here."""
    # The console must first be unlocked with the owner's passkey (checked against NepSec Intel's key).
    if not console_gate.console_unlocked(request.cookies.get(console_gate.UNLOCK_COOKIE)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=console_gate.LOCKED)
    principal = _principal(request, db, get_settings().console_cookie_name)
    if principal.role != "admin" or principal.is_demo:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requires admin role")
    return principal


def _principal(request: Request, db: Session, cookie_name: str) -> Principal:
    settings = get_settings()
    token = request.cookies.get(cookie_name)
    if not token or len(token) > 128:
        raise _unauthorized()

    session = db.execute(select(UserSession).where(UserSession.token_hash == sha256_hex(token))).scalar_one_or_none()
    now = datetime.now(UTC)
    if session is None or session.revoked_at is not None or session.expires_at <= now or session.last_seen_at <= now - timedelta(minutes=settings.session_idle_minutes):
        raise _unauthorized()

    user: User = session.user
    if not user.is_active:
        raise _unauthorized()
    if user.is_demo and not settings.demo_mode:
        raise _unauthorized()

    # CSRF: unsafe methods must echo the per-session token in a header. The
    # token is bound to this session (only its hash is stored server-side).
    if request.method in UNSAFE_METHODS:
        header = request.headers.get("x-csrf-token", "")
        if not header or not constant_time_equals(sha256_hex(header), session.csrf_hash):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid")

    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Change your temporary password to continue")

    # Sliding idle timeout, written at most once a minute to limit DB writes.
    if now - session.last_seen_at > timedelta(minutes=1):
        session.last_seen_at = now
        db.commit()

    return Principal(
        user_id=user.id,
        org_id=user.org_id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_demo=user.is_demo,
        session_id=session.id,
    )


def require_role(minimum: str) -> Callable[[Principal], Principal]:
    def checker(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.can(minimum):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Requires {minimum} role or higher")
        return principal

    return checker


def require_non_demo(principal: Principal = Depends(get_principal)) -> Principal:
    """Administrative operations are disabled for public demo accounts."""
    if principal.is_demo:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Disabled for demo accounts")
    return principal


def request_context(request: Request, principal: Principal | None = None) -> RequestContext:
    return RequestContext(
        org_id=principal.org_id if principal else None,
        user_id=principal.user_id if principal else None,
        actor_label=principal.email if principal else "anonymous",
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
    )


def get_ctx(request: Request, principal: Principal = Depends(get_principal)) -> RequestContext:
    return request_context(request, principal)


def get_console_ctx(request: Request, principal: Principal = Depends(get_console_principal)) -> RequestContext:
    return request_context(request, principal)


Viewer = Depends(require_role("viewer"))
Analyst = Depends(require_role("analyst"))
Lead = Depends(require_role("lead"))
Admin = Depends(require_role("admin"))
# Administration of users and data sources: only from the admin console.
ConsoleAdmin = Depends(get_console_principal)
