"""Microsoft log ingestion: Entra ID sign-ins and audit logs, Defender alerts, Windows events.

Payloads follow the documented Graph and Azure Monitor shapes, with synthetic
values (RFC 5737 addresses, reserved domains).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from app.connectors.microsoft import map_records
from tests.helpers import create_source


def _at(minutes: float) -> str:
    return (datetime.now(UTC) - timedelta(minutes=30) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def _signin(minutes: float, code: int, ip: str = "203.0.113.45", user: str = "J.Alvarez@contoso.example") -> dict[str, Any]:
    return {
        "id": f"signin-{minutes}-{code}",
        "createdDateTime": _at(minutes),
        "userPrincipalName": user,
        "appDisplayName": "Office 365 Exchange Online",
        "clientAppUsed": "Browser",
        "ipAddress": ip,
        "status": {"errorCode": code, "failureReason": "Invalid username or password." if code else None},
        "deviceDetail": {"displayName": "", "operatingSystem": "Windows10"},
        "location": {"city": "Example City", "countryOrRegion": "XX"},
    }


def _post(api, key: str, fmt: str, body: Any):
    return api.client.post(f"/api/v1/ingest/microsoft/{fmt}", json=body, headers={"Authorization": f"Bearer {key}"})


def _alerts(api) -> list[dict[str, Any]]:
    return api.get("/api/v1/alerts", params={"page_size": 100}).json()["items"]


def test_entra_signins_feed_password_guessing_rule(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Entra ID")
    records = [_signin(i * 0.5, 50126) for i in range(6)] + [_signin(5, 0)]
    r = _post(admin, key, "entra-signin", {"value": records})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 7 and body["skipped"] == 0 and body["alerts_created"] == 1
    assert any(a["rule_id"] == "SF-AUTH-001" for a in _alerts(admin))


def test_mfa_interrupts_are_skipped_not_counted_as_failures(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Entra ID")
    records = [_signin(i * 0.5, 50074) for i in range(8)] + [_signin(5, 0)]
    body = _post(admin, key, "entra-signin", records).json()
    assert body["inserted"] == 1 and body["skipped"] == 8 and body["alerts_created"] == 0


def test_azure_monitor_export_envelope() -> None:
    record = {"time": _at(1), "category": "SignInLogs", "properties": _signin(1, 50126)}
    events, skipped = map_records("entra-signin", {"records": [record]})
    assert skipped == 0 and events[0].event_type == "auth.failure"
    assert events[0].user_name == "j.alvarez@contoso.example" and events[0].src_ip == "203.0.113.45"


def test_entra_audit_new_global_admin(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Entra ID audit")
    actor = {"user": {"userPrincipalName": "attacker@contoso.example", "ipAddress": "198.51.100.23"}}
    records = [
        {"id": "a1", "activityDateTime": _at(1), "activityDisplayName": "Add user", "result": "success", "category": "UserManagement", "initiatedBy": actor,
         "targetResources": [{"type": "User", "userPrincipalName": "svc-backup@contoso.example"}]},
        {"id": "a2", "activityDateTime": _at(3), "activityDisplayName": "Add member to role", "result": "success", "category": "RoleManagement", "initiatedBy": actor,
         "targetResources": [{"type": "User", "userPrincipalName": "svc-backup@contoso.example",
                              "modifiedProperties": [{"displayName": "Role.DisplayName", "oldValue": None, "newValue": "\"Global Administrator\""}]}]},
        {"id": "a3", "activityDateTime": _at(4), "activityDisplayName": "Update application", "result": "success", "category": "ApplicationManagement", "initiatedBy": actor, "targetResources": []},
    ]  # fmt: skip
    body = _post(admin, key, "entra-audit", {"value": records}).json()
    assert body["inserted"] == 2 and body["skipped"] == 1 and body["alerts_created"] == 1
    alert = next(a for a in _alerts(admin) if a["rule_id"] == "SF-IAM-001")
    assert "Global Administrator" in alert["title"]


def test_defender_alerts_are_promoted_by_severity(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Defender XDR")

    def alert(i: int, severity: str) -> dict[str, Any]:
        return {
            "id": f"da{i}",
            "title": f"Suspicious PowerShell command line {i}",
            "severity": severity,
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": _at(i),
            "alertWebUrl": f"https://security.microsoft.com/alerts/da{i}",
            "mitreTechniques": ["T1059.001"],
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "fin-ws-014.contoso.example"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"userPrincipalName": "j.alvarez@contoso.example"}},
            ],
        }

    body = _post(admin, key, "defender-alert", {"value": [alert(1, "high"), alert(2, "low"), alert(3, "informational")]}).json()
    assert body["inserted"] == 3 and body["alerts_created"] == 1
    promoted = next(a for a in _alerts(admin) if a["rule_id"] == "SF-EXT-001")
    assert promoted["severity"] == "high" and "Suspicious PowerShell" in promoted["title"]

    # Forwarding the same alert again after a status change updates rather than duplicates.
    again = {**alert(1, "high"), "status": "inProgress"}
    body2 = _post(admin, key, "defender-alert", [again]).json()
    assert body2["inserted"] == 1 and body2["alerts_created"] == 0


def test_windows_security_events(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "DC01 Security log")
    t0 = datetime.now(UTC) - timedelta(minutes=20)

    def ps_date(minutes: float) -> str:  # Windows PowerShell 5.1 ConvertTo-Json date format
        return f"/Date({int((t0 + timedelta(minutes=minutes)).timestamp() * 1000)})/"

    records = [
        {"EventID": 4625, "TimeCreated": ps_date(i * 0.3), "Computer": "DC01.corp.example", "LogName": "Security",
         "EventData": {"TargetUserName": "b.chen", "TargetDomainName": "CORP", "IpAddress": "203.0.113.77", "LogonType": "10"}}
        for i in range(6)
    ] + [
        {"EventID": 4624, "TimeCreated": ps_date(3), "Computer": "DC01.corp.example", "LogName": "Security",
         "EventData": {"TargetUserName": "b.chen", "TargetDomainName": "CORP", "IpAddress": "203.0.113.77", "LogonType": "10"}},
        {"EventID": 4624, "TimeCreated": ps_date(3), "Computer": "DC01.corp.example", "LogName": "Security",
         "EventData": {"TargetUserName": "DC01$", "IpAddress": "-"}},
        {"EventID": 1102, "TimeCreated": ps_date(8), "Computer": "DC01.corp.example", "LogName": "Security", "EventData": {"SubjectUserName": "b.chen"}},
        {"EventID": 4688, "TimeCreated": ps_date(9), "Computer": "FIN-WS-014", "LogName": "Security",
         "EventData": {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                       "SubjectUserName": "b.chen", "SubjectDomainName": "CORP"}},
        {"EventID": 9999, "TimeCreated": ps_date(10), "Computer": "DC01", "LogName": "Security"},
    ]  # fmt: skip
    body = _post(admin, key, "windows-event", records).json()
    assert body["inserted"] == 9 and body["skipped"] == 2
    rules = {a["rule_id"] for a in _alerts(admin)}
    assert {"SF-AUTH-001", "SF-DEF-001", "SF-PROC-001"} <= rules


def test_log_analytics_security_event_xml_and_sysmon() -> None:
    xml = '<EventData xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Data Name="TargetUserName">Domain Admins</Data><Data Name="MemberName">CN=New Admin,OU=Users,DC=corp,DC=example</Data></EventData>'
    rows = [
        {"TimeGenerated": _at(1), "Computer": "DC01", "EventID": 4728, "EventData": xml},
        {
            "TimeGenerated": _at(2),
            "Computer": "FIN-WS-014",
            "EventID": 22,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventData": {"QueryName": "invoice-portal.example", "Image": "C:\\x\\chrome.exe"},
        },
        {"TimeGenerated": _at(3), "Computer": "FIN-WS-014", "EventID": 7036, "Channel": "System", "EventData": {"param1": "Windows Event Log", "param2": "stopped"}},
    ]
    events, skipped = map_records("windows-event", rows)
    assert skipped == 0
    group, dns, svc = events
    assert group.event_type == "iam.group_member_added" and group.group_name == "Domain Admins" and group.target_user == "New Admin"
    assert dns.event_type == "dns.query" and dns.domain == "invoice-portal.example" and dns.process_name == "chrome.exe"
    assert svc.event_type == "service.stopped" and svc.process_name == "eventlog"


def test_microsoft_ingest_requires_key_and_known_format(app) -> None:
    app_client = TestClient(app)
    assert app_client.post("/api/v1/ingest/microsoft/entra-signin", json=[]).status_code == 401
    assert app_client.post("/api/v1/ingest/microsoft/okta", json=[], headers={"Authorization": "Bearer sfk_x"}).status_code in (401, 404, 422)


def test_microsoft_ingest_rejects_oversized_batches(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Entra ID")
    r = _post(admin, key, "entra-signin", [{"id": i} for i in range(501)])
    assert r.status_code == 413


def test_garbage_records_are_skipped(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "Entra ID")
    body = _post(admin, key, "defender-alert", ["text", 5, {"title": None}, {"no": "fields"}]).json()
    assert body["received"] == 0 and body["skipped"] == 2
