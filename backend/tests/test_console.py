"""The admin console: administration answers only to a sign-in made from the console's own address."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import CONSOLE, PASSWORD, Api, unlock_token


def test_the_console_sign_in_answers_only_from_its_address_and_only_for_administrators(app, make_user) -> None:
    admin, analyst = make_user("admin"), make_user("analyst")
    client = TestClient(app)
    client.cookies.set("console_gate", unlock_token())
    body = {"email": admin.email, "password": PASSWORD}
    # From anywhere else it does not exist.
    assert client.post("/api/v1/auth/console-login", json=body).status_code == 404
    assert client.post("/api/v1/auth/console-login", json=body, headers={"Origin": "https://sentinelforge.kuinkel.com"}).status_code == 404
    # A correct password that is not an administrator's gets the same answer as a wrong one.
    refused = client.post("/api/v1/auth/console-login", json={"email": analyst.email, "password": PASSWORD}, headers={"Origin": CONSOLE})
    wrong = client.post("/api/v1/auth/console-login", json={"email": admin.email, "password": "Not-the-password-1"}, headers={"Origin": CONSOLE})
    assert refused.status_code == wrong.status_code == 401 and refused.json() == wrong.json()
    signed = client.post("/api/v1/auth/console-login", json=body, headers={"Origin": CONSOLE})
    assert signed.status_code == 200 and "sf_console" in signed.cookies and "sf_session" not in signed.cookies and "sf_csrf" not in signed.cookies


def test_the_apps_own_session_cannot_administer_and_the_console_cannot_use_the_app(app, make_user) -> None:
    admin = make_user("admin")
    in_app = Api(TestClient(app)).login(admin.email)
    assert in_app.get("/api/v1/admin/users").status_code == 401
    assert in_app.client.post("/api/v1/data-sources", json={"name": "x1", "source_type": "dns"}, headers={"X-CSRF-Token": in_app.csrf}).status_code == 401

    console = Api(TestClient(app)).console_login(admin.email)
    assert [u["email"] for u in console.get("/api/v1/admin/users").json()] == [admin.email]
    assert console.get("/api/v1/admin/system").json()["migration_revision"]
    created = console.post("/api/v1/data-sources", json={"name": "Firewall", "source_type": "fortigate"})
    assert created.status_code == 201 and created.json()["ingest_key"].startswith("sfk_")
    assert [s["name"] for s in console.get("/api/v1/admin/data-sources").json()] == ["Firewall"]
    # The console's cookie is not a session for the app itself.
    assert console.get("/api/v1/incidents").status_code == 401
    # Without its CSRF token a change is refused, and signing out ends it.
    assert console.client.post("/api/v1/data-sources", json={"name": "x2", "source_type": "dns"}).status_code == 403
    assert console.post("/api/v1/auth/console-logout").status_code == 204
    assert console.get("/api/v1/admin/users").status_code == 401


def test_nothing_is_checked_before_the_console_is_unlocked_with_a_passkey(app, make_user) -> None:
    admin = make_user("admin")
    client = TestClient(app)
    body = {"email": admin.email, "password": PASSWORD}
    locked = client.post("/api/v1/auth/console-login", json=body, headers={"Origin": CONSOLE})
    assert locked.status_code == 401 and "passkey" in locked.json()["detail"]
    client.cookies.set("console_gate", unlock_token(expires_in=-10))
    assert client.post("/api/v1/auth/console-login", json=body, headers={"Origin": CONSOLE}).status_code == 401
    client.cookies.set("console_gate", unlock_token()[:-4] + "AAAA")
    assert client.post("/api/v1/auth/console-login", json=body, headers={"Origin": CONSOLE}).status_code == 401
    client.cookies.set("console_gate", unlock_token())
    signed = client.post("/api/v1/auth/console-login", json=body, headers={"Origin": CONSOLE})
    assert signed.status_code == 200
    # The admin routes ask for it too: without it, the console sign-in alone is not enough.
    client.cookies.delete("console_gate")
    assert client.get("/api/v1/admin/users").status_code == 401
