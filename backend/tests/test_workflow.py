"""End-to-end incident workflow: ingest -> detect -> alert -> incident -> notes -> closure -> report."""

from __future__ import annotations

from sqlalchemy import select

from app.models import AuditLog
from tests.helpers import Api, brute_force_events, create_source, ingest


def test_full_incident_workflow(api_for, db) -> None:
    admin = api_for("admin")
    key = create_source(admin)

    # 1. Ingest synthetic events through the machine API; detection runs automatically.
    r = ingest(admin.client, key, brute_force_events())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"received": 7, "inserted": 7, "duplicates": 0, "alerts_created": 1, "alerts_updated": 0, "skipped": 0}

    # 2. The alert is visible in the triage queue (idempotent re-ingest is tested separately).
    alerts = admin.get("/api/v1/alerts").json()
    assert alerts["total"] == 1
    alert = alerts["items"][0]
    assert alert["rule_id"] == "SF-AUTH-001" and alert["severity"] == "high" and alert["confidence"] == "medium"
    assert alert["occurrence_count"] == 7

    # 3. The alert explains which rule fired and the evidence behind it.
    detail = admin.get(f"/api/v1/alerts/{alert['id']}").json()
    assert detail["rule"]["id"] == "SF-AUTH-001" and detail["rule"]["false_positives"]
    assert len(detail["events"]) == 7 and detail["events"][0]["raw"] == {}
    assert detail["alert"]["evidence_summary"]["failure_count"] == 6

    # 4. Escalate the alert into a new incident.
    analyst = api_for("analyst")
    r = analyst.post(f"/api/v1/alerts/{alert['id']}/escalate", json={})
    assert r.status_code == 200, r.text
    incident_id = r.json()["incident_id"]
    assert r.json()["reference"] == "INC-0001"

    inc = analyst.get(f"/api/v1/incidents/{incident_id}").json()
    assert inc["status"] == "new" and inc["alert_count"] == 1 and inc["event_count"] == 7
    assert len(analyst.get(f"/api/v1/incidents/{incident_id}/events").json()) == 7
    evidence = analyst.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    assert evidence[0]["evidence_type"] == "alert" and len(evidence[0]["sha256"]) == 64

    # 5. Notes and status transitions.
    r = analyst.post(f"/api/v1/incidents/{incident_id}/notes", json={"body": "Source address has no prior history."})
    assert r.status_code == 201
    # Adding a note bumps the version, so the stale copy is refreshed first.
    v = analyst.get(f"/api/v1/incidents/{incident_id}").json()["version"]
    assert v == inc["version"] + 1
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": v, "status": "resolved"})
    assert r.status_code == 422  # new -> resolved is not allowed
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": v, "status": "investigating"})
    assert r.status_code == 200, r.text
    inc = r.json()
    assert inc["acknowledged_at"] is not None

    # Stale version is rejected (optimistic concurrency).
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": v, "status": "contained"})
    assert r.status_code == 409

    for target in ("contained", "resolved"):
        r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": inc["version"], "status": target})
        assert r.status_code == 200, r.text
        inc = r.json()

    # Closing requires a verdict and reason.
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": inc["version"], "status": "closed"})
    assert r.status_code == 422
    r = analyst.post(
        f"/api/v1/incidents/{incident_id}/transition",
        json={"version": inc["version"], "status": "closed", "verdict": "true_positive", "closure_reason": "Password reset and sessions revoked."},
    )
    assert r.status_code == 200, r.text
    inc = r.json()
    assert inc["status"] == "closed" and inc["verdict"] == "true_positive" and inc["closed_at"]

    # Closed incidents are read-only.
    assert analyst.post(f"/api/v1/incidents/{incident_id}/notes", json={"body": "late"}).status_code == 409

    # 6. Timeline and report.
    timeline = analyst.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    kinds = {i["kind"] for i in timeline}
    assert {"event", "alert", "note", "status"} <= kinds
    report = analyst.get(f"/api/v1/incidents/{incident_id}/report").json()
    assert report["incident"]["verdict"] == "true_positive"
    assert report["detection_rules"][0]["id"] == "SF-AUTH-001"
    assert any(t["technique"] == "T1110" for t in report["attack_mapping"])
    md = analyst.get(f"/api/v1/incidents/{incident_id}/report", params={"format": "markdown"})
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    for heading in ("## Timeline", "## Supporting evidence", "## IOC findings", "## ATT&CK mapping", "## Limitations"):
        assert heading in md.text

    # 7. Audit trail covers the important actions.
    actions = set(db.execute(select(AuditLog.action)).scalars())
    assert {
        "data_source.created",
        "ingest.batch",
        "alert.created",
        "incident.created",
        "incident.alert_linked",
        "incident.note_added",
        "incident.status_changed",
        "alert.escalated",
    } <= actions


def test_reingest_is_idempotent(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin)
    events = brute_force_events()
    assert ingest(admin.client, key, events).json()["inserted"] == 7
    again = ingest(admin.client, key, events).json()
    assert again["inserted"] == 0 and again["duplicates"] == 7 and again["alerts_created"] == 0
    assert admin.get("/api/v1/alerts").json()["total"] == 1


def test_detection_rerun_does_not_duplicate_alerts(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin)
    ingest(admin.client, key, brute_force_events())
    r = admin.post("/api/v1/detections/run", json={"hours": 24})
    assert r.status_code == 200 and r.json()["alerts_created"] == 0 and r.json()["alerts_updated"] == 1
    alert = admin.get("/api/v1/alerts").json()["items"][0]
    assert alert["occurrence_count"] == 7


def test_reopen_requires_lead_and_reason(api_for, make_user) -> None:
    analyst = api_for("analyst")
    inc = analyst.post("/api/v1/incidents", json={"title": "Manual test incident", "severity": "low"}).json()
    r = analyst.post(
        f"/api/v1/incidents/{inc['id']}/transition",
        json={"version": inc["version"], "status": "closed", "verdict": "false_positive", "closure_reason": "Test traffic from the lab."},
    )
    inc = r.json()
    assert inc["status"] == "closed"
    assert analyst.post(f"/api/v1/incidents/{inc['id']}/transition", json={"version": inc["version"], "status": "open", "reason": "new evidence"}).status_code == 403

    from fastapi.testclient import TestClient

    lead_user = make_user("lead", "acme")
    lead = Api(TestClient(analyst.client.app)).login(lead_user.email)
    assert lead.post(f"/api/v1/incidents/{inc['id']}/transition", json={"version": inc["version"], "status": "open"}).status_code == 422
    r = lead.post(f"/api/v1/incidents/{inc['id']}/transition", json={"version": inc["version"], "status": "open", "reason": "New evidence from EDR."})
    assert r.status_code == 200 and r.json()["status"] == "open" and r.json()["verdict"] is None
