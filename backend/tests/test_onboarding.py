"""Emailed onboarding: temporary password, forced change, one-time password links, Resend client."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.config import get_settings
from app.models import PasswordResetToken
from app.security import validate_password_strength
from app.services import mail
from tests.helpers import Api

NEW_PASSWORD = "Brand-New-Passw0rd"


@pytest.fixture
def outbox(monkeypatch) -> list[mail.Email]:
    sent: list[mail.Email] = []

    def fake_send(message: mail.Email) -> mail.SendResult:
        sent.append(message)
        return mail.SendResult(True, provider_id=f"msg-{len(sent)}")

    monkeypatch.setattr(mail, "send_email", fake_send)
    return sent


def _token(message: mail.Email) -> str:
    m = re.search(r"/reset-password#token=([A-Za-z0-9_-]+)", message.text)
    assert m, message.text
    return m.group(1)


def _temp_password(message: mail.Email) -> str:
    m = re.search(r"temporary password: (\S+)", message.text)
    assert m, message.text
    return m.group(1)


def _invite(admin: Api, email: str = "new.analyst@acme.test", name: str = "New Analyst", role: str = "analyst") -> dict[str, Any]:
    r = admin.post("/api/v1/admin/users", json={"email": email, "display_name": name, "role": role})
    assert r.status_code == 201, r.text
    return r.json()


def test_invite_email_has_temp_password_link_and_system_info(api_for, outbox) -> None:
    admin = api_for("admin")
    body = _invite(admin)
    assert body["email_sent"] is True and "temporary_password" not in body and "password_link" not in body
    [message] = outbox
    assert message.to == "new.analyst@acme.test"
    assert "added to SentinelForge IR" in message.subject and "Acme SOC" in message.subject
    temp = _temp_password(message)
    validate_password_strength(temp)
    for fact in ("integrated into the Acme SOC", "Your role: analyst", "Added by", "Detection rules: 11 active rules", "Session policy", "/login"):
        assert fact in message.text, fact
    assert temp in message.html and _token(message) in message.html
    actions = [e["action"] for e in admin.get("/api/v1/audit", params={"page_size": 50}).json()["items"]]
    assert "user.invite_emailed" in actions
    # The audit trail never holds the temporary password.
    assert temp not in str(admin.get("/api/v1/audit", params={"page_size": 50}).json())


def test_temporary_password_must_be_changed_before_anything_else(app, api_for, outbox) -> None:
    admin = api_for("admin")
    _invite(admin)
    temp = _temp_password(outbox[0])
    user = Api(TestClient(app)).login("new.analyst@acme.test", temp)
    assert user.user["must_change_password"] is True
    blocked = user.get("/api/v1/alerts")
    assert blocked.status_code == 403 and "temporary password" in blocked.json()["detail"]
    assert user.get("/api/v1/auth/me").status_code == 200
    assert user.post("/api/v1/auth/password", json={"current_password": temp, "new_password": NEW_PASSWORD}).status_code == 204
    assert user.get("/api/v1/auth/me").json()["must_change_password"] is False
    assert user.get("/api/v1/alerts").status_code == 200
    # Choosing a password also retires the emailed link, so the mailbox alone cannot take the account over.
    assert TestClient(app).post("/api/v1/auth/reset-password/check", json={"token": _token(outbox[0])}).status_code == 400


def test_invite_link_sets_password_once(app, api_for, outbox) -> None:
    admin = api_for("admin")
    _invite(admin)
    token = _token(outbox[0])
    anon = TestClient(app)
    check = anon.post("/api/v1/auth/reset-password/check", json={"token": token})
    assert check.status_code == 200 and check.json()["email"] == "new.analyst@acme.test" and check.json()["purpose"] == "invite"
    weak = anon.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422
    assert anon.post("/api/v1/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}).status_code == 204
    # One-time: the link and the temporary password stop working.
    assert anon.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "Another-Passw0rd-x"}).status_code == 400
    assert anon.post("/api/v1/auth/login", json={"email": "new.analyst@acme.test", "password": _temp_password(outbox[0])}).status_code == 401
    user = Api(TestClient(app)).login("new.analyst@acme.test", NEW_PASSWORD)
    assert user.user["must_change_password"] is False


def test_admin_reset_email_revokes_sessions_and_earlier_links(app, api_for, make_user, outbox, db) -> None:
    admin = api_for("admin")
    member = make_user("analyst")
    session = Api(TestClient(app)).login(member.email)
    first = admin.post(f"/api/v1/admin/users/{member.id}/send-reset")
    assert first.status_code == 200 and first.json()["email_sent"] is True
    second = admin.post(f"/api/v1/admin/users/{member.id}/send-reset")
    assert second.status_code == 200
    old, new = _token(outbox[0]), _token(outbox[1])
    # A reset sends a link only; it never issues a new temporary password.
    assert outbox[1].subject == "Reset your SentinelForge IR password" and "temporary password" not in outbox[1].text
    anon = TestClient(app)
    assert anon.post("/api/v1/auth/reset-password", json={"token": old, "new_password": NEW_PASSWORD}).status_code == 400
    assert session.get("/api/v1/auth/me").status_code == 200  # current password and session still valid until the link is used
    assert anon.post("/api/v1/auth/reset-password", json={"token": new, "new_password": NEW_PASSWORD}).status_code == 204
    assert session.get("/api/v1/auth/me").status_code == 401


def test_expired_link_is_rejected(app, api_for, outbox, db) -> None:
    admin = api_for("admin")
    _invite(admin)
    db.execute(update(PasswordResetToken).values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    db.commit()
    r = TestClient(app).post("/api/v1/auth/reset-password/check", json={"token": _token(outbox[0])})
    assert r.status_code == 400 and "expired" in r.json()["detail"]


def test_reset_is_admin_only_and_org_scoped(api_for, make_user, outbox) -> None:
    admin, analyst = api_for("admin"), api_for("analyst")
    stranger = make_user("analyst", org="other")
    member = make_user("viewer")
    assert analyst.post(f"/api/v1/admin/users/{member.id}/send-reset").status_code == 403
    assert admin.post(f"/api/v1/admin/users/{stranger.id}/send-reset").status_code == 404
    assert outbox == []


def test_without_email_the_admin_sees_the_secrets_once(api_for) -> None:
    admin = api_for("admin")
    body = _invite(admin)
    assert body["email_sent"] is False and "not configured" in body["email_error"]
    validate_password_strength(body["temporary_password"])
    assert "/reset-password#token=" in body["password_link"]
    actions = [e["action"] for e in admin.get("/api/v1/audit", params={"page_size": 50}).json()["items"]]
    assert "user.invite_email_failed" in actions


def test_names_are_escaped_in_html_email(api_for, outbox) -> None:
    admin = api_for("admin")
    _invite(admin, name='<img src=x onerror="alert(1)">')
    assert "<img" not in outbox[0].html and "&lt;img" in outbox[0].html


def test_resend_client_request_and_errors(monkeypatch) -> None:
    monkeypatch.setenv("RESEND_API_KEY", "re_test_key")
    monkeypatch.setenv("MAIL_FROM", "SentinelForge IR <no-reply@example.test>")
    get_settings.cache_clear()
    seen: list[httpx.Request] = []
    real = httpx.Client

    def run(status: int, body: dict[str, Any]) -> mail.SendResult:
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(status, json=body)

        monkeypatch.setattr(mail.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
        return mail.send_email(mail.Email(to="a@example.test", subject="s", html="<p>h</p>", text="t"))

    ok = run(200, {"id": "abc"})
    assert ok.sent and ok.provider_id == "abc"
    request = seen[0]
    assert str(request.url) == mail.RESEND_URL and request.headers["authorization"] == "Bearer re_test_key"
    assert b'"to":["a@example.test"]' in request.content.replace(b" ", b"")
    bad = run(403, {"name": "validation_error", "message": "The example.test domain is not verified."})
    assert not bad.sent and "403" in bad.error and "not verified" in bad.error
    get_settings.cache_clear()
