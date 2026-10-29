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
from app.services import email_layout as layout
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


# Where a new account can start: (icon, name, what it does, page).
START_HERE = (
    ("alerts", "Alert queue", "Triage what the rules raised", "/alerts"),
    ("incidents", "Incidents", "Investigate and respond", "/incidents"),
    ("events", "Events", "Search every ingested log", "/events"),
    ("playbooks", "Playbooks", "Step-by-step response", "/playbooks"),
    ("intel", "Threat intel", "Look up IPs, domains, hashes", "/threat-intel"),
    ("detections", "Detections", "Rules and their tests", "/detections"),
    ("coverage", "ATT&CK coverage", "What is and is not covered", "/attack-coverage"),
    ("reports", "Reports", "Evidence-backed write-ups", "/reports"),
)


def _password_card(temp_password: str) -> str:
    return layout.card(
        layout.icon("key") + '<div style="margin-top:12px;font-size:13px;color:#667085;">Your temporary password</div>'
        f'<div style="margin-top:6px;font:700 22px Consolas,Menlo,monospace;letter-spacing:1px;color:#1e1b4b;">{escape(temp_password)}</div>'
        '<div style="margin-top:8px;font-size:12.5px;line-height:1.5;color:#667085;">You will be asked to replace it the first time you sign in. Do not share it.</div>'
    )


def _system_rows(user: User, facts: SystemFacts) -> list[tuple[str, str]]:
    rows = [
        ("Organisation", facts.organization),
        ("Your sign-in", user.email),
        ("Your role", f"{user.role}: {ROLE_SUMMARY.get(user.role, '')}"),
    ]
    rows += [
        ("Sign-in address", f"{_base_url()}/login"),
        ("Platform", f"SentinelForge IR {facts.version} ({facts.environment})"),
        ("Detection rules", f"{facts.rules} active rules"),
        ("Connected data sources", str(facts.data_sources)),
        ("Session policy", f"{facts.session_hours} hours maximum, signed out after {facts.idle_minutes} minutes idle"),
        ("Password policy", f"At least {MIN_PASSWORD_LENGTH} characters, upper and lower case letters and a digit"),
    ]
    return rows


def invite_email(user: User, facts: SystemFacts, temp_password: str, link: str) -> Email:
    hours = get_settings().password_link_hours
    rows = _system_rows(user, facts)
    subject = f"You have been added to SentinelForge IR ({facts.organization})"
    html = layout.page(
        title=subject,
        kind="Account",
        heading=f"Welcome, {user.display_name}",
        lead=f"Your account is ready: you are now part of the {facts.organization} incident response workspace on SentinelForge IR.",
        top_html=_password_card(temp_password),
        body_html=(
            f'<p style="margin:16px 0 14px;font-size:13.5px;line-height:1.6;color:#475467;text-align:center;">Or choose your own password now. '
            f"The link works once and expires in {hours} hours.</p>"
            + layout.button("Set your password", link)
            + f'<p style="margin:10px 0 0;font-size:12px;color:#98a2b3;word-break:break-all;text-align:center;">If the button does not work, open: {escape(link)}</p>'
            + layout.section_title("Your access")
            + layout.details(rows)
            + layout.section_title("Where to start")
            + layout.grid([(name, label, note, f"{_base_url()}{path}", "Open") for name, label, note, path in START_HERE])
        ),
        button_html=layout.button("Sign in to SentinelForge", f"{_base_url()}/login"),
        footer="You get this email because an administrator of your organisation added you. If you did not expect it, contact your administrator.",
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


def reset_email(user: User, facts: SystemFacts, link: str) -> Email:
    hours = get_settings().password_link_hours
    subject = "Reset your SentinelForge IR password"
    rows = [("Organisation", facts.organization), ("Account", user.email), ("Sign-in address", f"{_base_url()}/login")]
    html = layout.page(
        title=subject,
        kind="Security",
        heading="Reset your password",
        lead=f"Hello {user.display_name}, a password reset was issued for your account. Choose a new password with the button below.",
        top_html=layout.card(
            layout.icon("lock") + f'<div style="margin-top:12px;font-size:15px;font-weight:700;color:#101828;">The link works once and expires in {hours} hours</div>'
            '<div style="margin-top:6px;font-size:13px;line-height:1.55;color:#667085;">Your current password keeps working until you use it. '
            "Setting a new password signs you out of every session.</div>"
        ),
        body_html=layout.section_title("Account")
        + layout.details(rows)
        + f'<p style="margin:16px 0 0;font-size:12px;color:#98a2b3;word-break:break-all;text-align:center;">If the button does not work, open: {escape(link)}</p>',
        button_html=layout.button("Choose a new password", link),
        footer="You get this email because a reset was issued for your account. If you did not ask for it, contact your administrator.",
    )
    text = (
        f"Hello {user.display_name},\n\n"
        f"A password reset was issued for your SentinelForge IR account.\n"
        f"Choose a new password with this one-time link (expires in {hours} hours):\n  {link}\n\n"
        "Your current password keeps working until you use the link. Setting a new password signs you out of every session.\n\n"
        + "\n".join(f"  {k}: {v}" for k, v in rows)
        + "\n\nIf you did not expect this message, contact your administrator.\n"
    )
    return Email(to=user.email, subject=subject, html=html, text=text)
