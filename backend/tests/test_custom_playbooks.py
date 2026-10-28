"""Custom playbooks: building, rule suggestions, manual tasks, automated steps and approvals."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import Api, brute_force_events, create_source, ingest

STEPS = [
    {"kind": "action", "action": "collect_related_evidence", "title": "Pull related events"},
    {"kind": "task", "title": "Call the user to confirm the sign-in", "instructions": "Use the number in the HR directory, not one from email."},
    {"kind": "action", "action": "simulate_firewall_block", "title": "Block the source address"},
]


def _setup(app, api_for, make_user):
    admin = api_for("admin")
    key = create_source(admin)
    ingest(admin.client, key, brute_force_events())
    analyst = api_for("analyst")
    alert = analyst.get("/api/v1/alerts").json()["items"][0]
    incident_id = analyst.post(f"/api/v1/alerts/{alert['id']}/escalate", json={}).json()["incident_id"]
    lead = Api(TestClient(app)).login(make_user("lead", "acme").email)
    return analyst, lead, incident_id


def test_lead_builds_playbook_and_it_is_suggested_for_matching_incidents(app, api_for, make_user) -> None:
    analyst, lead, incident_id = _setup(app, api_for, make_user)
    body = {"name": "Account takeover", "description": "Password guessing that worked", "steps": STEPS, "trigger_rules": ["SF-AUTH-001"]}
    assert analyst.post("/api/v1/custom-playbooks", json=body).status_code == 403  # building is a lead's job
    r = lead.post("/api/v1/custom-playbooks", json=body)
    assert r.status_code == 201, r.text
    lead.post("/api/v1/custom-playbooks", json={"name": "Phishing", "steps": STEPS[1:2], "trigger_rules": ["SF-MAIL-001"]})
    listed = analyst.get("/api/v1/custom-playbooks", params={"incident_id": incident_id}).json()
    assert [(p["name"], p["suggested"]) for p in listed] == [("Account takeover", True), ("Phishing", False)]

    bad = {**body, "steps": [{"kind": "action", "action": "wipe_everything", "title": "x"}]}
    assert lead.post("/api/v1/custom-playbooks", json=bad).status_code == 422
    assert lead.post("/api/v1/custom-playbooks", json={**body, "trigger_rules": ["SF-NOPE-9"]}).status_code == 422


def test_running_a_custom_playbook_end_to_end(app, api_for, make_user) -> None:
    analyst, lead, incident_id = _setup(app, api_for, make_user)
    pid = lead.post("/api/v1/custom-playbooks", json={"name": "Account takeover", "steps": STEPS, "trigger_rules": ["SF-AUTH-001"]}).json()["id"]
    run = analyst.post(f"/api/v1/custom-playbooks/{pid}/start", json={"incident_id": incident_id}).json()
    base = f"/api/v1/custom-playbook-runs/{run['id']}/steps"

    # Step 1 runs the built-in playbook and links its response action.
    r = analyst.post(f"{base}/0", json={"action": "run"}).json()
    assert r["steps"][0]["status"] == "done" and r["steps"][0]["playbook_run_id"]
    # Manual tasks cannot be "run"; automated steps cannot be ticked off.
    assert analyst.post(f"{base}/1", json={"action": "run"}).status_code == 422
    assert analyst.post(f"{base}/2", json={"action": "complete"}).status_code == 422
    # Step 2: the analyst's note becomes evidence on the incident.
    r = analyst.post(f"{base}/1", json={"action": "complete", "note": "User confirmed they did not sign in."}).json()
    assert r["steps"][1]["status"] == "done" and r["steps"][1]["by"]
    evidence = analyst.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    assert any(e["evidence_type"] == "analyst_observation" and "Call the user" in e["title"] for e in evidence)

    # Step 3 is gated: it waits for a different lead, then the run completes.
    r = analyst.post(f"{base}/2", json={"action": "run", "parameters": {"ip_addresses": ["203.0.113.45"]}}).json()
    assert r["steps"][2]["status"] == "awaiting_approval" and r["status"] == "in_progress"
    assert analyst.post(f"{base}/2", json={"action": "run"}).status_code == 409
    action = lead.get("/api/v1/response-actions", params={"status": ["pending_approval"]}).json()["items"][0]
    assert lead.post(f"/api/v1/response-actions/{action['id']}/decision", json={"decision": "approved", "reason": "Confirmed takeover"}).status_code == 200
    [run] = analyst.get("/api/v1/custom-playbook-runs", params={"incident_id": incident_id}).json()
    assert run["steps"][2]["status"] == "done" and run["status"] == "completed" and run["completed_at"]


def test_skipping_needs_a_reason_and_steps_can_be_reopened(app, api_for, make_user) -> None:
    analyst, lead, incident_id = _setup(app, api_for, make_user)
    pid = lead.post("/api/v1/custom-playbooks", json={"name": "Checklist", "steps": STEPS[1:2]}).json()["id"]
    run = analyst.post(f"/api/v1/custom-playbooks/{pid}/start", json={"incident_id": incident_id}).json()
    step = f"/api/v1/custom-playbook-runs/{run['id']}/steps/0"
    assert analyst.post(step, json={"action": "skip"}).status_code == 422
    r = analyst.post(step, json={"action": "skip", "note": "User on leave; HR confirmed"}).json()
    assert r["steps"][0]["status"] == "skipped" and r["status"] == "completed"
    r = analyst.post(step, json={"action": "reopen"}).json()
    assert r["steps"][0]["status"] == "pending" and r["status"] == "in_progress" and r["completed_at"] is None
    assert analyst.post(f"/api/v1/custom-playbook-runs/{run['id']}/steps/9", json={"action": "complete"}).status_code == 404

    # Archiving hides the playbook from the list but keeps past runs.
    assert lead.client.delete(f"/api/v1/custom-playbooks/{pid}", headers={"X-CSRF-Token": lead.csrf or ""}).status_code == 204
    assert analyst.get("/api/v1/custom-playbooks").json() == []
    assert len(analyst.get("/api/v1/custom-playbook-runs", params={"incident_id": incident_id}).json()) == 1


def test_custom_playbooks_are_tenant_isolated(app, api_for, make_user) -> None:
    _, lead, incident_id = _setup(app, api_for, make_user)
    pid = lead.post("/api/v1/custom-playbooks", json={"name": "Acme only", "steps": STEPS[1:2]}).json()["id"]
    other = Api(TestClient(app)).login(make_user("lead", "globex").email)
    assert other.get("/api/v1/custom-playbooks").json() == []
    assert other.client.patch(f"/api/v1/custom-playbooks/{pid}", json={"name": "x"}, headers={"X-CSRF-Token": other.csrf or ""}).status_code == 404
    assert other.post(f"/api/v1/custom-playbooks/{pid}/start", json={"incident_id": incident_id}).status_code == 404
