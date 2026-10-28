"""Transactional email through the Resend HTTP API.

Message bodies can contain temporary passwords and one-time links, so they are
never logged; only the outcome is reported to the caller (and audited there).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from app.config import get_settings

RESEND_URL = "https://api.resend.com/emails"

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    html: str
    text: str


@dataclass(frozen=True)
class SendResult:
    sent: bool
    # Short, secret-free reason for audit and the admin UI when not sent.
    error: str | None = None
    provider_id: str | None = None


def mail_configured() -> bool:
    key = get_settings().resend_api_key
    return bool(key and key.get_secret_value())


def send_email(message: Email) -> SendResult:
    settings = get_settings()
    if not mail_configured():
        return SendResult(False, "Email is not configured (RESEND_API_KEY is not set)")
    assert settings.resend_api_key is not None
    try:
        with httpx.Client(timeout=settings.mail_timeout_seconds, headers={"User-Agent": "SentinelForge-IR/0.1"}) as client:
            r = client.post(
                RESEND_URL,
                headers={"Authorization": f"Bearer {settings.resend_api_key.get_secret_value()}"},
                json={"from": settings.mail_from, "to": [message.to], "subject": message.subject, "html": message.html, "text": message.text},
            )
    except httpx.TimeoutException:
        return SendResult(False, "The email provider timed out")
    except httpx.HTTPError as exc:
        log.warning("email provider unreachable: %s", type(exc).__name__)
        return SendResult(False, "The email provider could not be reached")
    if r.status_code >= 400:
        # Resend returns {"name": ..., "message": ...}; the message names the problem
        # (unverified domain, invalid key) without echoing the request body.
        try:
            detail = str(r.json().get("message") or "")[:200]
        except ValueError:
            detail = ""
        log.warning("email provider rejected the message: HTTP %s %s", r.status_code, detail)
        return SendResult(False, f"The email provider rejected the message (HTTP {r.status_code}){': ' + detail if detail else ''}")
    try:
        provider_id = str(r.json().get("id") or "") or None
    except ValueError:
        provider_id = None
    return SendResult(True, provider_id=provider_id)
