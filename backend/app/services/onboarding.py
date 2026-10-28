"""Account onboarding and password reset: temporary passwords, one-time links and their emails.

Links carry the token in the URL fragment (``/reset-password#token=...``), which
browsers never send to a server, so it stays out of access logs and Referer headers.
"""

from __future__ import annotations

import secrets
import string
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.detection.rules import ALL_RULES
from app.models import DataSource, PasswordResetToken, User
from app.security import MIN_PASSWORD_LENGTH, new_token, sha256_hex
from app.services.mail import Email

ROLE_SUMMARY = {
    "viewer": "read-only access to alerts, incidents, events and reports",
    "analyst": "triage alerts, investigate incidents, enrich indicators and request response actions",
    "lead": "everything an analyst can do, plus approving response actions and reopening incidents",
    "admin": "everything a lead can do, plus managing users and data sources",
}

# No look-alike characters (0/O, 1/l/I), so the password survives being read aloud or retyped.
_ALPHABET = "".join(c for c in string.ascii_letters + string.digits if c not in "0O1lI")


def temporary_password(length: int = 16) -> str:
    """A random password that always satisfies validate_password_strength."""
    length = max(length, MIN_PASSWORD_LENGTH)
    while True:
        candidate = "".join(secrets.choice(_ALPHABET) for _ in range(length))
        if any(c.islower() for c in candidate) and any(c.isupper() for c in candidate) and any(c.isdigit() for c in candidate):
            return candidate


def issue_token(db: Session, user: User, purpose: str, created_by: uuid.UUID | None) -> str:
    """Create a one-time token, invalidating any earlier unused ones. Returns the raw token."""
    now = datetime.now(UTC)
    db.execute(update(PasswordResetToken).where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)).values(used_at=now))
    token = new_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=sha256_hex(token),
            purpose=purpose,
            created_by=created_by,
            expires_at=now + timedelta(hours=get_settings().password_link_hours),
        )
    )
    return token


def find_valid_token(db: Session, token: str) -> PasswordResetToken | None:
    if not token or len(token) > 128:
        return None
    row = db.execute(select(PasswordResetToken).where(PasswordResetToken.token_hash == sha256_hex(token))).scalar_one_or_none()
    if row is None or row.used_at is not None or row.expires_at <= datetime.now(UTC):
        return None
    user = row.user
    if not user.is_active or user.is_demo or user.removed_at is not None:
        return None
    return row


def password_link(token: str) -> str:
    return f"{_base_url()}/reset-password#token={token}"


def _base_url() -> str:
    return get_settings().app_base_url.rstrip("/")


# --- email content ------------------------------------------------------------------


@dataclass(frozen=True)
class SystemFacts:
    organization: str
    version: str
    environment: str
    rules: int
    data_sources: int
    session_hours: int
    idle_minutes: int


def system_facts(db: Session, user: User) -> SystemFacts:
    s = get_settings()
    sources = db.execute(select(func.count()).select_from(DataSource).where(DataSource.org_id == user.org_id)).scalar_one()
    return SystemFacts(
        organization=user.organization.name,
        version=s.app_version,
        environment=s.app_env,
        rules=len(ALL_RULES),
        data_sources=int(sources),
        session_hours=s.session_ttl_hours,
        idle_minutes=s.session_idle_minutes,
    )


_STYLE_BODY = "margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827"
_STYLE_CARD = "max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:28px"
_STYLE_BUTTON = "display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:600;padding:11px 18px;border-radius:8px"
_STYLE_CODE = (
    "font-family:Consolas,Menlo,monospace;font-size:16px;letter-spacing:1px;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:6px;padding:8px 12px;display:inline-block"
)
_STYLE_TD_LABEL = "padding:6px 12px 6px 0;color:#6b7280;white-space:nowrap;vertical-align:top"
_STYLE_TD = "padding:6px 0;color:#111827"


def _table(rows: list[tuple[str, str]]) -> str:
    cells = "".join(f'<tr><td style="{_STYLE_TD_LABEL}">{escape(k)}</td><td style="{_STYLE_TD}">{escape(v)}</td></tr>' for k, v in rows)
    return f'<table role="presentation" style="border-collapse:collapse;font-size:14px;margin:8px 0 4px">{cells}</table>'


def _wrap(title: str, inner: str) -> str:
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>{escape(title)}</title></head>'
        f'<body style="{_STYLE_BODY}"><div style="{_STYLE_CARD}">'
        '<p style="margin:0 0 20px;font-weight:700;font-size:15px;color:#2563eb">SentinelForge IR</p>'
        f"{inner}"
        '<hr style="border:none;border-top:1px solid #e5e7eb;margin:24px 0 12px">'
        '<p style="margin:0;font-size:12px;color:#6b7280">This is an automated message from SentinelForge IR. '
        "We never ask for your password by email or phone. If you did not expect this message, contact your administrator.</p>"
        "</div></body></html>"
    )


def _system_rows(user: User, facts: SystemFacts, invited_by: str | None) -> list[tuple[str, str]]:
    rows = [
        ("Organisation", facts.organization),
        ("Your sign-in", user.email),
        ("Your role", f"{user.role}: {ROLE_SUMMARY.get(user.role, '')}"),
    ]
    if invited_by:
        rows.append(("Added by", invited_by))
    rows += [
        ("Sign-in address", f"{_base_url()}/login"),
        ("Platform", f"SentinelForge IR {facts.version} ({facts.environment})"),
        ("Detection rules", f"{facts.rules} active rules"),
        ("Connected data sources", str(facts.data_sources)),
        ("Session policy", f"{facts.session_hours} hours maximum, signed out after {facts.idle_minutes} minutes idle"),
        ("Password policy", f"At least {MIN_PASSWORD_LENGTH} characters, upper and lower case letters and a digit"),
    ]
    return rows


def invite_email(user: User, facts: SystemFacts, temp_password: str, link: str, invited_by: str | None) -> Email:
    hours = get_settings().password_link_hours
    rows = _system_rows(user, facts, invited_by)
    subject = f"You have been added to SentinelForge IR ({facts.organization})"
    html = _wrap(
        subject,
        f'<h1 style="margin:0 0 12px;font-size:20px">Welcome, {escape(user.display_name)}</h1>'
        f'<p style="margin:0 0 16px;font-size:15px;line-height:1.5">Your account has been created and you are now integrated into the '
        f"<strong>{escape(facts.organization)}</strong> incident response workspace on SentinelForge IR.</p>"
        '<h2 style="margin:20px 0 8px;font-size:15px">1. Set your password</h2>'
        f'<p style="margin:0 0 12px;font-size:14px;line-height:1.5">Choose your own password with this one-time link. It expires in {hours} hours.</p>'
        f'<p style="margin:0 0 16px"><a href="{escape(link)}" style="{_STYLE_BUTTON}">Set your password</a></p>'
        '<h2 style="margin:20px 0 8px;font-size:15px">2. Or sign in with your temporary password</h2>'
        f'<p style="margin:0 0 8px"><span style="{_STYLE_CODE}">{escape(temp_password)}</span></p>'
        '<p style="margin:0 0 16px;font-size:13px;color:#6b7280">You will be asked to replace it the first time you sign in. Do not share it.</p>'
        '<h2 style="margin:20px 0 4px;font-size:15px">Your access</h2>'
        f"{_table(rows)}"
        f'<p style="margin:12px 0 0;font-size:13px;color:#6b7280;word-break:break-all">If the button does not work, open: {escape(link)}</p>',
    )
    text_rows = "\n".join(f"  {k}: {v}" for k, v in rows)
    text = (
        f"Welcome, {user.display_name}\n\n"
        f"Your account has been created and you are now integrated into the {facts.organization} incident response workspace on SentinelForge IR.\n\n"
        f"1. Set your password (one-time link, expires in {hours} hours):\n  {link}\n\n"
        f"2. Or sign in with your temporary password: {temp_password}\n"
        "  You will be asked to replace it the first time you sign in. Do not share it.\n\n"
        f"Your access\n{text_rows}\n\n"
        "We never ask for your password by email or phone. If you did not expect this message, contact your administrator.\n"
    )
    return Email(to=user.email, subject=subject, html=html, text=text)


def reset_email(user: User, facts: SystemFacts, link: str, requested_by: str | None) -> Email:
    hours = get_settings().password_link_hours
    subject = "Reset your SentinelForge IR password"
    who = f" at the request of {requested_by}" if requested_by else ""
    rows = [("Organisation", facts.organization), ("Account", user.email), ("Sign-in address", f"{_base_url()}/login")]
    html = _wrap(
        subject,
        f'<h1 style="margin:0 0 12px;font-size:20px">Reset your password</h1>'
        f'<p style="margin:0 0 16px;font-size:15px;line-height:1.5">Hello {escape(user.display_name)}, a password reset was issued for your account{escape(who)}. '
        f"Use this one-time link to choose a new password. It expires in {hours} hours.</p>"
        f'<p style="margin:0 0 16px"><a href="{escape(link)}" style="{_STYLE_BUTTON}">Choose a new password</a></p>'
        '<p style="margin:0 0 8px;font-size:14px;line-height:1.5">Your current password keeps working until you use the link. '
        "Setting a new password signs you out of every session.</p>"
        f"{_table(rows)}"
        f'<p style="margin:12px 0 0;font-size:13px;color:#6b7280;word-break:break-all">If the button does not work, open: {escape(link)}</p>',
    )
    text = (
        f"Hello {user.display_name},\n\n"
        f"A password reset was issued for your SentinelForge IR account{who}.\n"
        f"Choose a new password with this one-time link (expires in {hours} hours):\n  {link}\n\n"
        "Your current password keeps working until you use the link. Setting a new password signs you out of every session.\n\n"
        + "\n".join(f"  {k}: {v}" for k, v in rows)
        + "\n\nIf you did not expect this message, contact your administrator.\n"
    )
    return Email(to=user.email, subject=subject, html=html, text=text)
