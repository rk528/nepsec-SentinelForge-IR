"""Alerts raised by hand, links between incidents, alerts and events in every direction, and NepSec Intel's findings."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tests.helpers import brute_force_events, create_source, ingest


def _events(api: Any) -> list[dict[str, Any]]:
    r = api.get("/api/v1/events", params={"page_size": 100})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def _delete(api: Any, url: str):
    return api.client.delete(url, headers=api._headers())


def _incident(api: Any, title: str = "Investigate the VPN") -> dict[str, Any]:
    r = api.post("/api/v1/incidents", json={"title": title, "severity": "medium"})
    assert r.status_code == 201, r.text
    return r.json()


def test_an_analyst_raises_an_alert_from_picked_events_and_a_viewer_cannot(api_for) -> None:
    admin = api_for("admin")
    ingest(admin.client, create_source(admin), brute_force_events())
    analyst = api_for("analyst")
    picked = [e["id"] for e in _events(analyst)[:2]]

    r = analyst.post("/api/v1/alerts", json={"title": "User reported a strange sign-in prompt", "description": "Called the help desk.", "severity": "high", "event_ids": picked})
    assert r.status_code == 201, r.text
    alert = r.json()
    assert alert["rule_id"] == "SF-MAN-001" and alert["rule_name"] == "Raised by an analyst" and alert["status"] == "new" and alert["severity"] == "high"

    detail = analyst.get(f"/api/v1/alerts/{alert['id']}").json()
    assert sorted(e["id"] for e in detail["events"]) == sorted(picked)
    assert detail["rule"]["name"] == "Raised by an analyst" and detail["rule"]["required_telemetry"]
    # It is in the queue with the detections, but is not a detection rule of its own.
    assert alert["id"] in [a["id"] for a in analyst.get("/api/v1/alerts").json()["items"]]
    assert "SF-MAN-001" not in [rule["id"] for rule in analyst.get("/api/v1/detections").json()]

    viewer = api_for("viewer")
    assert viewer.post("/api/v1/alerts", json={"title": "Not allowed", "severity": "low"}).status_code == 403
    # Events of another organisation cannot be named.
    other = api_for("analyst", org="other")
    assert other.post("/api/v1/alerts", json={"title": "Borrowed events", "severity": "low", "event_ids": picked}).status_code == 404


def test_an_alert_raised_into_an_incident_brings_its_events(api_for) -> None:
    admin = api_for("admin")
    ingest(admin.client, create_source(admin), brute_force_events())
    analyst = api_for("analyst")
    incident = _incident(analyst)
    picked = [e["id"] for e in _events(analyst)[:3]]
    alert = analyst.post("/api/v1/alerts", json={"title": "Seen by the network team", "severity": "critical", "event_ids": picked, "incident_id": incident["id"]}).json()
    assert alert["status"] == "escalated" and alert["incident_id"] == incident["id"]
    assert sorted(e["id"] for e in analyst.get(f"/api/v1/incidents/{incident['id']}/events").json()) == sorted(picked)
    # The incident takes the alert's severity when it is higher.
    assert analyst.get(f"/api/v1/incidents/{incident['id']}").json()["severity"] == "critical"


def test_links_go_every_way_between_incidents_alerts_and_events(api_for) -> None:
    admin = api_for("admin")
    later = {"event_time": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(), "event_type": "process.start", "host": "fin-ws-07", "user_name": "fin.user01", "process_name": "notepad.exe"}
    ingest(admin.client, create_source(admin), [*brute_force_events(), later])
    analyst = api_for("analyst")
    detected = analyst.get("/api/v1/alerts").json()["items"][0]
    events = _events(analyst)
    incident = _incident(analyst)

    # Incident to alerts: the detected alert comes in with its events.
    r = analyst.post(f"/api/v1/incidents/{incident['id']}/alerts", json={"alert_ids": [detected["id"]]})
    assert r.status_code == 201 and r.json() == {"linked": 1}
    assert [a["id"] for a in analyst.get(f"/api/v1/incidents/{incident['id']}/alerts").json()] == [detected["id"]]
    linked = {e["id"] for e in analyst.get(f"/api/v1/incidents/{incident['id']}/events").json()}
    assert linked and analyst.post(f"/api/v1/incidents/{incident['id']}/alerts", json={"alert_ids": [detected["id"]]}).json() == {"linked": 0}

    # Alert to events: an event the rule did not match is added to the alert, and so to its incident.
    extra = next(e["id"] for e in events if e["id"] not in linked)
    r = analyst.post(f"/api/v1/alerts/{detected['id']}/events", json={"event_ids": [extra], "reason": "Same user, minutes later"})
    assert r.status_code == 201 and r.json() == {"linked": 1}
    assert extra in [e["id"] for e in analyst.get(f"/api/v1/alerts/{detected['id']}").json()["events"]]
    assert extra in {e["id"] for e in analyst.get(f"/api/v1/incidents/{incident['id']}/events").json()}

    # Event to both: the event page lists what it belongs to.
    refs = analyst.get(f"/api/v1/events/{extra}").json()
    assert [a["id"] for a in refs["alerts"]] == [detected["id"]] and [i["id"] for i in refs["incidents"]] == [incident["id"]]

    # Incident to events, and back out again.
    assert _delete(analyst, f"/api/v1/incidents/{incident['id']}/events/{extra}").status_code == 204
    assert extra not in {e["id"] for e in analyst.get(f"/api/v1/incidents/{incident['id']}/events").json()}
    assert _delete(analyst, f"/api/v1/incidents/{incident['id']}/events/{extra}").status_code == 404

    # Alert out of its incident.
    r = _delete(analyst, f"/api/v1/alerts/{detected['id']}/incident")
    assert r.status_code == 200 and r.json()["incident_id"] is None and r.json()["status"] == "acknowledged"
    assert analyst.get(f"/api/v1/incidents/{incident['id']}/alerts").json() == []
    assert _delete(analyst, f"/api/v1/alerts/{detected['id']}/incident").status_code == 409

    # A viewer reads the links but changes none.
    viewer = api_for("viewer")
    assert viewer.post(f"/api/v1/incidents/{incident['id']}/alerts", json={"alert_ids": [detected["id"]]}).status_code == 403
    assert viewer.post(f"/api/v1/alerts/{detected['id']}/events", json={"event_ids": [extra]}).status_code == 403


def _finding(title: str, severity: str, outcome: str) -> dict[str, Any]:
    return {
        "event_time": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        "event_type": "security.alert",
        "outcome": outcome,
        "message": f"NepSec Intel attack surface: {title} (example.org)",
        "dst_ip": "203.0.113.7",
        "raw": {
            "product": "NepSec Intel",
            "kind": "surface",
            "title": f"{title} (example.org)",
            "severity": severity,
            "link": "https://nepsecintel.kuinkel.com/surface",
            "detail": "3389/tcp",
            "cves": ["CVE-2019-0708 (CVSS 9.8 critical; exploited in attacks (CISA))"],
            "open_incident": severity in ("critical", "high"),
        },
    }


def test_nepsec_intel_findings_become_alerts_and_a_high_one_opens_an_incident_once(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "NepSec Intel")
    r = ingest(admin.client, key, [_finding("Remote desktop is open", "high", "high"), _finding("No DMARC record", "low", "medium")])
    assert r.status_code == 200 and r.json()["alerts_created"] == 2

    analyst = api_for("analyst")
    alerts = {a["title"]: a for a in analyst.get("/api/v1/alerts").json()["items"]}
    high, low = alerts["NepSec Intel attack surface: Remote desktop is open (example.org)"], alerts["NepSec Intel attack surface: No DMARC record (example.org)"]
    # The severity NepSec Intel gave is kept, rather than the two the forwarded-alert rule knows.
    assert high["severity"] == "high" and low["severity"] == "low"
    assert high["status"] == "escalated" and high["incident_id"] and low["incident_id"] is None

    incident = analyst.get(f"/api/v1/incidents/{high['incident_id']}").json()
    assert incident["title"] == high["title"] and incident["source"] == "integration" and "nepsec-intel" in incident["tags"]
    detail = analyst.get(f"/api/v1/alerts/{high['id']}").json()["alert"]
    assert detail["evidence_summary"]["link"] == "https://nepsecintel.kuinkel.com/surface" and detail["evidence_summary"]["cves"]

    # Sending the same finding again the same day adds to its alert and opens no second incident.
    ingest(admin.client, key, [_finding("Remote desktop is open", "high", "high")])
    assert analyst.get("/api/v1/incidents").json()["total"] == 1
