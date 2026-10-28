"""Alert digest emails for people who opted in.

Called after each detection run. New alerts wait in a queue (``alerts.notified_at IS
NULL``); at most once per ``ALERT_EMAIL_INTERVAL_MINUTES`` per organisation, each
subscriber gets one email listing the queued alerts at or above their chosen severity,
and the queue is cleared. A burst of alerts therefore becomes one email, not fifty.

Alert titles and entities come from log data, so everything is HTML-escaped and the
email carries no raw event payloads, command output or links other than to the app.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from html import escape

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import audit
from app.config import get_settings
from app.models import Alert, Organization, User
from app.services import mail
from app.services.onboarding import _STYLE_BUTTON, _wrap

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOUR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563", "info": "#4b5563"}
MAX_LISTED = 20
QUEUE_HOURS = 24  # alerts older than this when first seen by the sender are cleared, not emailed


def _app_url(path: str) -> str:
    return get_settings().app_base_url.rstrip("/") + path


def _entity_line(a: Alert) -> str:
    e = a.entities or {}
    parts = [f"{k} {e[k]}" for k in ("host", "user", "src_ip") if e.get(k)]
    return " · ".join(str(p) for p in parts)


def digest_email(user: User, org_name: str, alerts: list[Alert]) -> mail.Email:
    shown = alerts[:MAX_LISTED]
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    worst = max(alerts, key=lambda a: SEVERITY_RANK.get(a.severity, 0)).severity
    breakdown = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if s in counts)
    subject = f"[SentinelForge] {len(alerts)} new alert{'s' if len(alerts) != 1 else ''} ({breakdown})"

    rows = "".join(
        '<tr><td style="padding:10px 0;border-top:1px solid #e5e7eb;vertical-align:top">'
        f'<span style="display:inline-block;min-width:64px;font-size:12px;font-weight:700;text-transform:uppercase;color:{SEVERITY_COLOUR.get(a.severity, "#4b5563")}">{escape(a.severity)}</span></td>'
        '<td style="padding:10px 0 10px 8px;border-top:1px solid #e5e7eb">'
        f'<a href="{escape(_app_url(f"/alerts/{a.id}"))}" style="color:#111827;font-weight:600;text-decoration:none">{escape(a.title)}</a>'
        f'<div style="font-size:12px;color:#6b7280;margin-top:2px">{escape(a.rule_id)}{" · " + escape(_entity_line(a)) if _entity_line(a) else ""}</div></td></tr>'
        for a in shown
    )
    more = len(alerts) - len(shown)
    html = _wrap(
        subject,
        f'<h1 style="margin:0 0 8px;font-size:20px">{len(alerts)} new alert{"s" if len(alerts) != 1 else ""} in {escape(org_name)}</h1>'
        f'<p style="margin:0 0 12px;font-size:14px;color:#374151">Highest severity: <strong>{escape(worst)}</strong>. Open each alert to triage it; nothing has been acted on automatically.</p>'
        f'<table role="presentation" style="border-collapse:collapse;width:100%;font-size:14px">{rows}</table>'
        + (f'<p style="margin:8px 0 0;font-size:13px;color:#6b7280">and {more} more.</p>' if more else "")
        + f'<p style="margin:20px 0 0"><a href="{escape(_app_url("/alerts?status=new"))}" style="{_STYLE_BUTTON}">Open the alert queue</a></p>'
        f'<p style="margin:20px 0 0;font-size:12px;color:#6b7280">You get these because alert emails are on for {escape(user.email)} '
        f"(severity {escape(user.alert_email_severity or '')} and above). Change or turn them off in Settings → Alert emails.</p>",
    )
    text = "\n".join(
        [f"{len(alerts)} new alert(s) in {org_name} ({breakdown}).", ""]
        + [f"[{a.severity.upper()}] {a.title} ({a.rule_id}) {_app_url(f'/alerts/{a.id}')}" for a in shown]
        + ([f"... and {more} more."] if more else [])
        + ["", f"Alert queue: {_app_url('/alerts?status=new')}", "Change or turn off alert emails in Settings → Alert emails."]
    )
    return mail.Email(to=user.email, subject=subject, html=html, text=text)


def send_pending(db: Session, org_id: uuid.UUID, now: datetime | None = None) -> dict[str, int]:
    """Email queued alerts if the organisation is due. Never raises; returns what happened."""
    # A savepoint keeps the caller's transaction (the ingested events) usable whatever happens here.
    savepoint = db.begin_nested()
    try:
        result = _send_pending(db, org_id, now or datetime.now(UTC))
        savepoint.commit()
        return result
    except Exception:  # a notification problem must never fail ingestion
        savepoint.rollback()
        log.exception("alert digest failed for org %s", org_id)
        return {"error": 1}


def _send_pending(db: Session, org_id: uuid.UUID, now: datetime) -> dict[str, int]:
    # Lock the organisation row so two concurrent ingest requests cannot both send.
    org = db.execute(select(Organization).where(Organization.id == org_id).with_for_update(skip_locked=True)).scalar_one_or_none()
    if org is None or org.is_demo or not mail.mail_configured():
        return {}
    interval = timedelta(minutes=get_settings().alert_email_interval_minutes)
    if org.alert_email_sent_at and now - org.alert_email_sent_at < interval:
        return {"deferred": 1}

    queued = list(db.execute(select(Alert).where(Alert.org_id == org_id, Alert.notified_at.is_(None))).scalars())
    if not queued:
        return {}
    fresh = [a for a in queued if a.created_at >= now - timedelta(hours=QUEUE_HOURS)]
    fresh.sort(key=lambda a: (-SEVERITY_RANK.get(a.severity, 0), a.created_at))

    subscribers = list(
        db.execute(
            select(User).where(
                User.org_id == org_id,
                User.alert_email_severity.is_not(None),
                User.is_active.is_(True),
                User.is_demo.is_(False),
                User.removed_at.is_(None),
            )
        ).scalars()
    )
    sent = failed = 0
    for user in subscribers:
        floor = SEVERITY_RANK.get(user.alert_email_severity or "", 99)
        theirs = [a for a in fresh if SEVERITY_RANK.get(a.severity, 0) >= floor]
        if not theirs:
            continue
        result = mail.send_email(digest_email(user, org.name, theirs))
        if result.sent:
            sent += 1
        else:
            failed += 1
            log.warning("alert digest to a subscriber failed: %s", result.error)

    db.execute(update(Alert).where(Alert.id.in_([a.id for a in queued])).values(notified_at=now))
    if sent or failed:
        org.alert_email_sent_at = now
        audit.record(
            db,
            audit.SYSTEM_CONTEXT,
            "alert.digest_emailed",
            target_type="organization",
            target_id=org_id,
            details={"alerts": len(fresh), "recipients": sent, "failed": failed},
            org_id=org_id,
        )
    return {"alerts": len(fresh), "sent": sent, "failed": failed}
