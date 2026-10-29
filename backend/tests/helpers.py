from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

PASSWORD = "Correct-Horse-42-battery"
# The admin console's address in tests (CONSOLE_ORIGINS in conftest).
CONSOLE = "https://console.test"
# Calls that only the admin console may make.
CONSOLE_PATHS = ("/api/v1/admin/", "/api/v1/data-sources", "/api/v1/auth/console-logout")


# The key the console's passkey unlock is signed with in tests, standing in for NepSec Intel's (see conftest).
UNLOCK_KEY = None


def unlock_token(expires_in: int = 3600) -> str:
    """A passkey unlock as NepSec Intel signs it: payload.signature, ES256, the signature as raw r||s."""
    import base64
    import json
    import time

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    b64 = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")  # noqa: E731
    payload = b64(json.dumps({"k": "gate", "c": "test", "iat": 0, "exp": int(time.time()) + expires_in}).encode())
    r, s = decode_dss_signature(UNLOCK_KEY.sign(payload.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{payload}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class Api:
    """Thin TestClient wrapper that sends the CSRF header after login."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.csrf: str | None = None
        self.console_csrf: str | None = None
        self.user: dict[str, Any] | None = None

    def _headers(self, extra: dict[str, str] | None = None, url: str = "") -> dict[str, str]:
        h = dict(extra or {})
        token = self.console_csrf if self.console_csrf and url.startswith(CONSOLE_PATHS) else self.csrf
        if token:
            h.setdefault("X-CSRF-Token", token)
        return h

    def get(self, url: str, **kw: Any):
        return self.client.get(url, **kw)

    def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None, **kw: Any):
        return self.client.post(url, json=json, headers=self._headers(headers, url), **kw)

    def patch(self, url: str, json: Any = None, headers: dict[str, str] | None = None, **kw: Any):
        return self.client.patch(url, json=json, headers=self._headers(headers, url), **kw)

    def delete(self, url: str, headers: dict[str, str] | None = None, **kw: Any):
        return self.client.delete(url, headers=self._headers(headers, url), **kw)

    def console_login(self, email: str, password: str = PASSWORD) -> Api:
        """Also sign in to the admin console, as an administrator does from its own address, once it is unlocked."""
        self.client.cookies.set("console_gate", unlock_token())
        r = self.client.post("/api/v1/auth/console-login", json={"email": email, "password": password}, headers={"Origin": CONSOLE})
        assert r.status_code == 200, r.text
        self.console_csrf = r.json()["csrf_token"]
        return self

    def login(self, email: str, password: str = PASSWORD) -> Api:
        r = self.client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        self.user = r.json()
        self.csrf = self.user["csrf_token"]
        return self


def brute_force_events(start: datetime | None = None, user: str = "fin.user01", src: str = "203.0.113.45") -> list[dict[str, Any]]:
    t = start or datetime.now(UTC) - timedelta(minutes=20)
    events = [
        {"event_time": (t + timedelta(seconds=20 * i)).isoformat(), "event_type": "auth.failure", "user_name": user, "src_ip": src, "host": "vpn-gw-01", "outcome": "failure"}
        for i in range(6)
    ]
    events.append({"event_time": (t + timedelta(minutes=4)).isoformat(), "event_type": "auth.success", "user_name": user, "src_ip": src, "host": "vpn-gw-01", "outcome": "success"})
    return events


def create_source(admin_api: Any, name: str = "VPN gateway") -> str:
    r = admin_api.post("/api/v1/data-sources", json={"name": name, "source_type": "custom"})
    assert r.status_code == 201, r.text
    return r.json()["ingest_key"]


def ingest(client: Any, key: str, events: list[dict[str, Any]]) -> Any:
    return client.post("/api/v1/ingest/events", json={"events": events}, headers={"Authorization": f"Bearer {key}"})
