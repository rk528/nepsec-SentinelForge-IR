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
from app.services import email_layout as layout
from app.services import mail

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOUR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563", "info": "#4b5563"}
SEVERITY_FILL = {"critical": "#fee4e2", "high": "#ffedd5", "medium": "#fef3c7", "low": "#f2f4f7", "info": "#f2f4f7"}
MAX_LISTED = 20
CARDS = 8  # the first alerts are shown as cards, the rest as lines
QUEUE_HOURS = 24  # alerts older than this when first seen by the sender are cleared, not emailed


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


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

    cards = [
        (
            f"sev-{a.severity}",
            _short(a.title, 70),
            _short(" · ".join(p for p in (a.rule_id, _entity_line(a)) if p), 44),
            _app_url(f"/alerts/{a.id}"),
            "View alert",
        )
        for a in shown[:CARDS]
    ]
    rest = shown[CARDS:]
    more = len(alerts) - len(shown)
    chips = "".join(
        f'<span style="display:inline-block;margin:3px;padding:3px 10px;border-radius:999px;background:{SEVERITY_FILL.get(sev, "#f2f4f7")};'
        f'color:{SEVERITY_COLOUR.get(sev, "#4b5563")};font-size:12px;font-weight:700;">{counts[sev]} {escape(sev)}</span>'
        for sev in ("critical", "high", "medium", "low", "info", "informational")
        if sev in counts
    )
    summary = layout.card(
        layout.icon(f"sev-{worst}")
        + f'<div style="margin-top:10px;font-size:30px;font-weight:700;line-height:1.1;color:{SEVERITY_COLOUR.get(worst, "#4b5563")};">{len(alerts)}</div>'
        f'<div style="margin-top:4px;font-size:13.5px;color:#344054;">new alert{"s" if len(alerts) != 1 else ""} waiting for triage</div>'
        f'<div style="margin-top:10px;">{chips}</div>'
    )
    listed = "".join(
        f'<tr><td style="padding:10px 16px;{"" if i == 0 else "border-top:1px solid #eaecf0;"}">'
        f'<span style="display:inline-block;min-width:64px;font-size:11px;font-weight:700;text-transform:uppercase;color:{SEVERITY_COLOUR.get(a.severity, "#4b5563")}">{escape(a.severity)}</span>'
        f'<a href="{escape(_app_url(f"/alerts/{a.id}"))}" style="color:#101828;font-size:13.5px;font-weight:600;text-decoration:none">{escape(a.title)}</a></td></tr>'
        for i, a in enumerate(rest)
    )
    body = layout.grid(cards)
    if listed:
        body += layout.section_title("More alerts") + (
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e4e7ec;border-radius:12px;border-collapse:separate;">'
            f"{listed}</table>"
        )
    if more:
        body += f'<p style="margin:10px 0 0;font-size:13px;color:#667085;text-align:center;">and {more} more in the queue.</p>'
    html = layout.page(
        title=subject,
        kind="Alert digest",
        heading=f"{len(alerts)} new alert{'s' if len(alerts) != 1 else ''} in {org_name}",
        lead=f"Highest severity: {worst}. Open each alert to triage it; nothing has been acted on automatically.",
        top_html=summary,
        body_html=body,
        button_html=layout.button("Open the alert queue", _app_url("/alerts?status=new")),
        footer=f"You get these because alert emails are on for {user.email} (severity {user.alert_email_severity or ''} and above). "
        "Change or turn them off in Settings, Alert emails.",
        preview=f"{len(alerts)} new alerts ({breakdown})",
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
