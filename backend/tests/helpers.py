from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

PASSWORD = "Correct-Horse-42-battery"


class Api:
    """Thin TestClient wrapper that sends the CSRF header after login."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.csrf: str | None = None
        self.user: dict[str, Any] | None = None

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = dict(extra or {})
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        return h

    def get(self, url: str, **kw: Any):
        return self.client.get(url, **kw)

    def post(self, url: str, json: Any = None, headers: dict[str, str] | None = None, **kw: Any):
        return self.client.post(url, json=json, headers=self._headers(headers), **kw)

    def patch(self, url: str, json: Any = None, headers: dict[str, str] | None = None, **kw: Any):
        return self.client.patch(url, json=json, headers=self._headers(headers), **kw)

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
