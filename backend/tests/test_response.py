"""Playbooks, approvals, separation of duties, idempotency, demo mode and dashboard."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models import AuditLog, Event, Organization
from app.services import demo
from tests.helpers import Api, brute_force_events, create_source, ingest


def _incident(api_for):
    admin = api_for("admin")
    key = create_source(admin)
    ingest(admin.client, key, brute_force_events())
    analyst = api_for("analyst")
    alert = analyst.get("/api/v1/alerts").json()["items"][0]
    incident_id = analyst.post(f"/api/v1/alerts/{alert['id']}/escalate", json={}).json()["incident_id"]
    return analyst, incident_id


def test_non_disruptive_playbooks_execute_and_record_evidence(api_for) -> None:
    analyst, incident_id = _incident(api_for)
    for pid in ("collect_related_evidence", "enrich_iocs", "prepare_summary", "propose_blocklist", "record_containment", "closure_report"):
        r = analyst.post(f"/api/v1/playbooks/{pid}/run", json={"incident_id": incident_id, "idempotency_key": f"k-{pid}-0001"})
        assert r.status_code == 201, (pid, r.text)
        assert r.json()["status"] == "completed", (pid, r.json())
    types = {e["evidence_type"] for e in analyst.get(f"/api/v1/incidents/{incident_id}/evidence").json()}
    assert {"alert", "playbook_output", "ioc_enrichment", "report"} <= types
    enrich = analyst.get("/api/v1/response-actions", params={"incident_id": incident_id}).json()
    assert enrich["total"] == 6 and all(a["status"] == "executed" for a in enrich["items"])


def test_playbook_idempotency(api_for) -> None:
    analyst, incident_id = _incident(api_for)
    body = {"incident_id": incident_id, "idempotency_key": "same-key-123"}
    first = analyst.post("/api/v1/playbooks/prepare_summary/run", json=body)
    second = analyst.post("/api/v1/playbooks/prepare_summary/run", json=body)
    assert first.status_code == 201 and second.status_code == 200
    assert first.json()["id"] == second.json()["id"] and second.json()["idempotent_replay"] is True
    assert analyst.get("/api/v1/response-actions", params={"incident_id": incident_id}).json()["total"] == 1
    # Re-using the key for a different playbook is a conflict, not a silent replay.
    assert analyst.post("/api/v1/playbooks/propose_blocklist/run", json=body).status_code == 409


def test_firewall_block_requires_approval_from_a_different_lead(app, api_for, make_user, db) -> None:
    analyst, incident_id = _incident(api_for)
    lead_a = Api(TestClient(app)).login(make_user("lead", "acme").email)
    lead_b = Api(TestClient(app)).login(make_user("lead", "acme").email)

    # Lead A requests the (simulated) block.
    r = lead_a.post(
        "/api/v1/playbooks/simulate_firewall_block/run", json={"incident_id": incident_id, "idempotency_key": "block-0001", "parameters": {"ip_addresses": ["203.0.113.45"]}}
    )
    assert r.status_code == 201 and r.json()["status"] == "awaiting_approval"
    action = lead_a.get("/api/v1/response-actions", params={"status": ["pending_approval"]}).json()["items"][0]
    assert action["requires_approval"] and action["simulated"] and action["rollback_plan"]

    # Analysts cannot approve; the requester cannot approve their own action.
    assert analyst.post(f"/api/v1/response-actions/{action['id']}/decision", json={"decision": "approved", "reason": "looks fine"}).status_code == 403
    assert lead_a.post(f"/api/v1/response-actions/{action['id']}/decision", json={"decision": "approved", "reason": "self approval"}).status_code == 403

    # A different lead approves; execution is simulated and recorded.
    r = lead_b.post(f"/api/v1/response-actions/{action['id']}/decision", json={"decision": "approved", "reason": "Confirmed guessing source."})
    assert r.status_code == 200, r.text
    done = r.json()
    assert done["status"] == "executed" and done["result"]["simulated"] is True
    assert done["result"]["would_apply"][0]["rule"] == "deny ip any host 203.0.113.45"
    assert done["approval"]["decision"] == "approved"
    # Approving twice is impossible.
    assert lead_b.post(f"/api/v1/response-actions/{action['id']}/decision", json={"decision": "approved", "reason": "again"}).status_code == 409
    actions = set(db.execute(select(AuditLog.action)).scalars())
    assert {"playbook.run", "response_action.approved", "response_action.executed"} <= actions


def test_block_refuses_internal_addresses(api_for) -> None:
    analyst, incident_id = _incident(api_for)
    for i, bad in enumerate((["10.0.0.5"], ["127.0.0.1"], ["not-an-ip"], [])):
        r = analyst.post(
            "/api/v1/playbooks/simulate_firewall_block/run", json={"incident_id": incident_id, "idempotency_key": f"bad-block-{i:04d}", "parameters": {"ip_addresses": bad}}
        )
        assert r.status_code == 422, (bad, r.text)


def test_cannot_close_incident_with_pending_action(api_for) -> None:
    analyst, incident_id = _incident(api_for)
    analyst.post(
        "/api/v1/playbooks/simulate_firewall_block/run", json={"incident_id": incident_id, "idempotency_key": "pending-001", "parameters": {"ip_addresses": ["203.0.113.45"]}}
    )
    inc = analyst.get(f"/api/v1/incidents/{incident_id}").json()
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": inc["version"], "status": "closed", "verdict": "true_positive", "closure_reason": "Handled."})
    assert r.status_code == 409
    action = analyst.get("/api/v1/response-actions", params={"status": ["pending_approval"]}).json()["items"][0]
    assert analyst.post(f"/api/v1/response-actions/{action['id']}/cancel").status_code == 200
    inc = analyst.get(f"/api/v1/incidents/{incident_id}").json()
    r = analyst.post(f"/api/v1/incidents/{incident_id}/transition", json={"version": inc["version"], "status": "closed", "verdict": "true_positive", "closure_reason": "Handled."})
    assert r.status_code == 200


# --- demo mode ----------------------------------------------------------------------------------


def test_demo_seed_login_and_reset(app, db) -> None:
    result = demo.seed_demo(db)
    db.commit()
    assert result["alerts"] > 10
    synthetic = db.execute(select(func.count()).select_from(Event).where(Event.is_synthetic.is_(False))).scalar_one()
    assert synthetic == 0  # every demo event is flagged synthetic

    c = TestClient(app)
    me = c.post("/api/v1/auth/demo", json={"role": "lead"}).json()
    api = Api(c)
    api.csrf = me["csrf_token"]
    assert me["is_demo"] and me["role"] == "lead"
    summary = api.get("/api/v1/dashboard/summary").json()
    assert summary["synthetic"] is True and summary["open_incidents"]["total"] >= 2
    assert summary["mtta"]["minutes"] is not None and summary["mtta"]["sample_size"] > 0
    # Demo accounts cannot perform administrative operations.
    assert api.post("/api/v1/admin/users", json={"email": "x@y.test", "display_name": "X", "role": "admin", "password": "Strong-password-1"}).status_code == 403
    # The seeded firewall block waits for a lead other than the requesting analyst.
    pending = api.get("/api/v1/response-actions", params={"status": ["pending_approval"]}).json()["items"]
    assert len(pending) == 1
    assert api.post(f"/api/v1/response-actions/{pending[0]['id']}/decision", json={"decision": "approved", "reason": "Demo approval"}).json()["status"] == "executed"

    with pytest.raises(ValueError):
        demo.reset_demo(db, "yes")
    assert demo.reset_demo(db, demo.RESET_CONFIRMATION) is True
    db.commit()
    assert db.execute(select(Organization).where(Organization.slug == "demo")).scalar_one_or_none() is None
    assert c.get("/api/v1/auth/me").status_code == 401


def test_demo_login_disabled_without_demo_mode(app, monkeypatch) -> None:
    from app.config import get_settings

    monkeypatch.setenv("DEMO_MODE", "false")
    get_settings.cache_clear()
    assert TestClient(app).post("/api/v1/auth/demo", json={"role": "analyst"}).status_code == 404


def test_dashboard_metrics_with_no_data(api_for) -> None:
    api = api_for("viewer")
    s = api.get("/api/v1/dashboard/summary", params={"days": 7}).json()
    assert s["open_incidents"]["total"] == 0
    assert s["mtta"] == {"minutes": None, "sample_size": 0}  # never fabricated
    assert len(s["incident_trend"]) == 8


def test_attack_coverage_reports_gaps_and_tests(api_for) -> None:
    api = api_for("analyst")
    before = api.get("/api/v1/attack/coverage").json()
    t1110 = next(t for t in before["techniques"] if t["technique"] == "T1110")
    assert t1110["coverage"] == "untested" and t1110["rules"] == ["SF-AUTH-001"]
    assert any(t["coverage"] == "gap" and t["gap_reason"] for t in before["techniques"])
    assert "not proof" in before["disclaimer"]
    results = api.post("/api/v1/detections/self-test").json()
    assert all(r["passed"] for r in results)
    after = api.get("/api/v1/attack/coverage").json()
    assert next(t for t in after["techniques"] if t["technique"] == "T1110")["coverage"] == "tested"
