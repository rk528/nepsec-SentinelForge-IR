"""Alert digest emails: opt-in, severity floor, pacing, escaping and failure isolation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from app.models import Organization
from app.services import mail
from tests.helpers import brute_force_events, create_source, ingest


@pytest.fixture
def outbox(monkeypatch) -> list[mail.Email]:
    sent: list[mail.Email] = []

    def fake_send(message: mail.Email) -> mail.SendResult:
        sent.append(message)
        return mail.SendResult(True, provider_id=f"msg-{len(sent)}")

    monkeypatch.setattr(mail, "mail_configured", lambda: True)
    monkeypatch.setattr(mail, "send_email", fake_send)
    return sent


def _subscribe(api, severity: str | None):
    r = api.patch("/api/v1/auth/me/notifications", json={"alert_email_severity": severity})
    assert r.status_code == 200, r.text
    return r.json()


def test_subscribers_get_one_digest_at_or_above_their_severity(api_for, outbox) -> None:
    admin = api_for("admin")
    analyst = api_for("analyst")
    lead = api_for("lead")
    api_for("viewer")  # not subscribed: gets nothing
    assert _subscribe(analyst, "high")["alert_email_severity"] == "high"
    _subscribe(lead, "critical")
    assert analyst.get("/api/v1/auth/me").json()["alert_email_severity"] == "high"

    key = create_source(admin)
    ingest(admin.client, key, brute_force_events())  # one high-severity SF-AUTH-001 alert
    assert [m.to for m in outbox] == [analyst.user["email"]]
    [email] = outbox
    assert email.subject == "[SentinelForge] 1 new alert (1 high)"
    assert "Sign-in succeeded for fin.user01" in email.html and "/alerts/" in email.text and "SF-AUTH-001" in email.text
    audit = admin.get("/api/v1/audit", params={"action": "alert.digest_emailed"}).json()["items"]
    assert audit and audit[0]["details"]["recipients"] == 1


def test_bursts_are_paced_and_queued_alerts_follow(api_for, outbox, db) -> None:
    admin = api_for("admin")
    analyst = api_for("analyst")
    _subscribe(analyst, "medium")
    key = create_source(admin)
    ingest(admin.client, key, brute_force_events(user="first.user"))
    # A second alert minutes later waits: the organisation was emailed less than 10 minutes ago.
    ingest(admin.client, key, brute_force_events(user="second.user", src="203.0.113.46"))
    assert len(outbox) == 1
    db.execute(update(Organization).values(alert_email_sent_at=datetime.now(UTC) - timedelta(minutes=11)))
    db.commit()
    # The next batch, even one without new alerts, flushes the queue.
    ingest(admin.client, key, [{"event_time": datetime.now(UTC).isoformat(), "event_type": "dns.query", "host": "ws-1", "domain": "example.org"}])
    assert len(outbox) == 2 and "second.user" in outbox[1].html and "first.user" not in outbox[1].html


def test_digest_escapes_log_controlled_text_and_can_be_turned_off(api_for, outbox) -> None:
    admin = api_for("admin")
    analyst = api_for("analyst")
    _subscribe(analyst, "low")
    key = create_source(admin)
    ingest(admin.client, key, brute_force_events(user="<img src=x onerror=alert(1)>"))
    [email] = outbox
    assert "<img src=x" not in email.html and "&lt;img src=x" in email.html
    assert _subscribe(analyst, None)["alert_email_severity"] is None
    assert analyst.patch("/api/v1/auth/me/notifications", json={"alert_email_severity": "everything"}).status_code == 422


def test_mail_failure_never_breaks_ingestion(api_for, monkeypatch) -> None:
    admin = api_for("admin")
    analyst = api_for("analyst")
    _subscribe(analyst, "high")

    def boom(message):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr(mail, "mail_configured", lambda: True)
    monkeypatch.setattr(mail, "send_email", boom)
    key = create_source(admin)
    r = ingest(admin.client, key, brute_force_events())
    assert r.status_code == 200 and r.json()["alerts_created"] == 1
