"""Microsoft log formats mapped to normalised events.

Accepted shapes for every format:

* Microsoft Graph API responses (``{"value": [...]}``) or bare Graph records.
* Azure Monitor diagnostic exports (``{"records": [...]}`` with ``properties``),
  as delivered by Event Hubs, Logic Apps or storage exports.
* Log Analytics query rows (``SigninLogs``, ``AuditLogs``, ``SecurityEvent``).
* The PowerShell shipper in ``connectors/windows`` for Windows event logs.

A mapper returns ``None`` for a record it does not translate (an unrelated
activity, a sign-in interrupt such as an MFA prompt, a machine-account logon).
Skipped records are counted, never guessed at.
"""

from __future__ import annotations

import ntpath
import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from app.schemas import EventIn

Record = dict[str, Any]

# Entra sign-in error codes that interrupt a sign-in rather than reject the
# credential (MFA required, "stay signed in?" prompt, password change due, ...).
# Counting them as failures would make every MFA prompt look like password guessing.
SIGNIN_INTERRUPTS = {50055, 50058, 50072, 50074, 50076, 50079, 50125, 50140, 50158, 50199, 81010, 81012, 81014}

_SERVICE_NAMES = {
    "windows event log": "eventlog",
    "sysmon": "sysmon",
    "sysmon64": "sysmon64",
    "microsoft defender antivirus service": "windefend",
    "windows defender antivirus service": "windefend",
}


def _unwrap(payload: Any) -> list[Record]:
    """A list of records from any of the accepted envelope shapes."""
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("value", "records", "events", "Records"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
        else:
            items = [payload]
    else:
        return []
    return [r for r in items if isinstance(r, dict)]


def _props(record: Record) -> Record:
    """Azure Monitor exports wrap the Graph-like body in ``properties``."""
    inner = record.get("properties")
    return {**record, **inner} if isinstance(inner, dict) else record


def _time(*values: Any) -> datetime | None:
    for v in values:
        if isinstance(v, str) and v:
            text = v.strip()
            # Windows PowerShell 5.1's ConvertTo-Json emits "/Date(1700000000000)/".
            if m := re.search(r"Date\((\d+)", text):
                return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
            text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                continue
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v in ("", "-", "::1", "127.0.0.1"):
        return None
    if v.startswith("::ffff:"):
        v = v[7:]
    return v


def _s(value: Any, limit: int = 255) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:limit] if text and text != "-" else None


def _trim(record: Record, keys: tuple[str, ...]) -> Record:
    return {k: record[k] for k in keys if record.get(k) not in (None, "", [], {})}


# --- Entra ID sign-in logs -------------------------------------------------------------


def entra_signin(record: Record) -> dict[str, Any] | None:
    r = _props(record)
    when = _time(r.get("createdDateTime"), r.get("TimeGenerated"), r.get("time"))
    user = _s(r.get("userPrincipalName") or r.get("UserPrincipalName"))
    status = r.get("status") or r.get("Status") or {}
    if isinstance(status, str):
        status = {}
    code = status.get("errorCode", r.get("ResultType"))
    try:
        code = int(code) if code not in (None, "") else None
    except (TypeError, ValueError):
        code = None
    if when is None or user is None or code is None or code in SIGNIN_INTERRUPTS:
        return None
    device = r.get("deviceDetail") or r.get("DeviceDetail") or {}
    location = r.get("location") or r.get("LocationDetails") or {}
    app = _s(r.get("appDisplayName") or r.get("AppDisplayName"), 120)
    where = ", ".join(x for x in (location.get("city"), location.get("countryOrRegion")) if isinstance(x, str) and x)
    reason = _s(status.get("failureReason") or r.get("ResultDescription"), 300)
    message = f"Entra ID sign-in to {app or 'an application'}" + (f" from {where}" if where else "") + (f": {reason}" if code and reason else "")
    return {
        "event_time": when,
        "event_type": "auth.success" if code == 0 else "auth.failure",
        "outcome": "success" if code == 0 else "failure",
        "host": _s(device.get("displayName")) if isinstance(device, dict) else None,
        "user_name": user.lower(),
        "src_ip": _ip(r.get("ipAddress") or r.get("IPAddress")),
        "message": message[:4000],
        "raw": {
            "source": "microsoft.entra.signin",
            "error_code": code,
            **_trim(r, ("id", "appDisplayName", "clientAppUsed", "conditionalAccessStatus", "riskLevelDuringSignIn", "correlationId")),
            "location": where or None,
            "operating_system": device.get("operatingSystem") if isinstance(device, dict) else None,
        },
    }


# --- Entra ID audit logs ----------------------------------------------------------------


def _modified(target: Record, name: str) -> str | None:
    for prop in target.get("modifiedProperties") or []:
        if isinstance(prop, dict) and prop.get("displayName") == name:
            value = prop.get("newValue")
            return _s(value.strip('"') if isinstance(value, str) else value)
    return None


def entra_audit(record: Record) -> dict[str, Any] | None:
    r = _props(record)
    activity = str(r.get("activityDisplayName") or r.get("OperationName") or "")
    result = str(r.get("result") or r.get("Result") or "").lower()
    when = _time(r.get("activityDateTime"), r.get("TimeGenerated"), r.get("time"))
    if when is None or result not in ("success", ""):
        return None
    targets = [t for t in (r.get("targetResources") or r.get("TargetResources") or []) if isinstance(t, dict)]
    initiated = r.get("initiatedBy") or r.get("InitiatedBy") or {}
    actor_user = initiated.get("user") if isinstance(initiated, dict) else None
    actor_app = initiated.get("app") if isinstance(initiated, dict) else None
    actor = _s((actor_user or {}).get("userPrincipalName")) or _s((actor_app or {}).get("displayName"))
    user_target = next((t for t in targets if str(t.get("type", "")).lower() == "user"), targets[0] if targets else {})
    target_user = _s(user_target.get("userPrincipalName") or user_target.get("displayName"))

    base = {
        "event_time": when,
        "outcome": "success",
        "user_name": actor.lower() if actor else None,
        "src_ip": _ip((actor_user or {}).get("ipAddress")),
        "target_user": target_user.lower() if target_user else None,
        "raw": {"source": "microsoft.entra.audit", "activity": activity, **_trim(r, ("id", "category", "correlationId", "loggedByService"))},
    }
    if activity == "Add user":
        return {**base, "event_type": "iam.user_created", "message": f"Entra ID: {actor or 'unknown actor'} created user {target_user}"}
    if activity in ("Add member to role", "Add eligible member to role", "Add member to role completed (PIM activation)"):
        role = None
        for t in targets:
            role = role or _modified(t, "Role.DisplayName")
        role = role or next((_s(t.get("displayName")) for t in targets if str(t.get("type", "")).lower() == "role"), None)
        return {**base, "event_type": "iam.group_member_added", "group_name": role, "message": f"Entra ID: {target_user} added to role {role}"}
    if activity == "Add member to group":
        group = None
        for t in targets:
            group = group or _modified(t, "Group.DisplayName")
        group = group or next((_s(t.get("displayName")) for t in targets if str(t.get("type", "")).lower() == "group"), None)
        return {**base, "event_type": "iam.group_member_added", "group_name": group, "message": f"Entra ID: {target_user} added to group {group}"}
    return None


# --- Microsoft Defender XDR / Graph security alerts --------------------------------------


def defender_alert(record: Record) -> dict[str, Any] | None:
    r = _props(record)
    title = _s(r.get("title") or r.get("AlertName") or r.get("Title"), 500)
    when = _time(r.get("createdDateTime"), r.get("firstActivityDateTime"), r.get("TimeGenerated"), r.get("Timestamp"))
    if title is None or when is None:
        return None
    severity = str(r.get("severity") or r.get("AlertSeverity") or r.get("Severity") or "unknown").lower()
    host = user = ip = None
    for ev in r.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("@odata.type", ""))
        if host is None and kind.endswith("deviceEvidence"):
            host = _s(ev.get("deviceDnsName") or ev.get("hostName"))
        elif user is None and kind.endswith("userEvidence"):
            account = ev.get("userAccount") or {}
            user = _s(account.get("userPrincipalName") or account.get("accountName"))
        elif ip is None and kind.endswith("ipEvidence"):
            ip = _ip(ev.get("ipAddress"))
    link = r.get("alertWebUrl")
    service = _s(r.get("serviceSource") or r.get("ProviderName") or "Microsoft Defender", 80)
    return {
        "event_time": when,
        "event_type": "security.alert",
        "outcome": severity[:32],
        "host": host or _s(r.get("CompromisedEntity")),
        "user_name": user.lower() if user else None,
        "src_ip": ip,
        "url": link if isinstance(link, str) and link.startswith("https://") else None,
        "message": f"{service}: {title}"[:4000],
        "raw": {
            "source": "microsoft.defender.alert",
            **_trim(r, ("id", "providerAlertId", "incidentId", "status", "category", "detectionSource", "serviceSource", "mitreTechniques", "classification")),
            "description": str(r.get("description") or r.get("Description") or "")[:1000] or None,
        },
    }


# --- Windows event logs (Security, System, Sysmon) ---------------------------------------


def _flat(record: Record) -> Record:
    """Merge EventData fields into the top level, whatever shape they arrive in."""
    out = dict(record)
    data = record.get("EventData")
    if isinstance(data, dict):
        out.update(data)
    elif isinstance(data, list):  # [{"Name": "TargetUserName", "Value": "x"}]
        for item in data:
            if isinstance(item, dict) and "Name" in item:
                out[item["Name"]] = item.get("Value", item.get("#text"))
    elif isinstance(data, str) and data.startswith("<"):  # Log Analytics SecurityEvent.EventData XML
        for name, value in re.findall(r'<Data Name="([^"]+)">([^<]*)</Data>', data):
            out.setdefault(name, value)
    return out


def _cn(value: Any) -> str | None:
    """'CN=New Admin,OU=Users,DC=corp,DC=local' -> 'New Admin'."""
    text = _s(value)
    if text and (m := re.match(r"CN=([^,]+)", text, re.I)):
        return m.group(1)
    return text


def _exe(value: Any) -> str | None:
    text = _s(value, 1024)
    return ntpath.basename(text).lower() if text else None


def _account(r: Record, *names: str) -> str | None:
    for n in names:
        v = _s(r.get(n))
        if v and v not in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON") and not v.endswith("$"):
            domain = _s(r.get(n.replace("UserName", "DomainName")))
            return (f"{domain}\\{v}" if domain and domain not in ("-", "NT AUTHORITY") and "UserName" in n else v).lower()
    return None


def windows_event(record: Record) -> dict[str, Any] | None:
    r = _flat(record)
    try:
        event_id = int(r.get("EventID") or r.get("Id") or r.get("EventId") or 0)
    except (TypeError, ValueError):
        return None
    when = _time(r.get("TimeCreated"), r.get("TimeGenerated"), r.get("UtcTime") and f"{r['UtcTime']}Z", r.get("@timestamp"))
    host = _s(r.get("Computer") or r.get("MachineName"))
    channel = str(r.get("Channel") or r.get("LogName") or r.get("ProviderName") or r.get("EventSourceName") or "").lower()
    if when is None:
        return None
    base: dict[str, Any] = {"event_time": when, "host": host.lower() if host else None, "raw": {"source": "microsoft.windows", "event_id": event_id, "channel": channel or None}}

    if "sysmon" in channel:
        if event_id == 1:
            hashes = str(r.get("Hashes") or "")
            sha = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes)
            return {
                **base,
                "event_type": "process.start",
                "user_name": _s(r.get("User"), 255),
                "process_name": _exe(r.get("Image")),
                "command_line": _s(r.get("CommandLine"), 8192),
                "parent_process": _exe(r.get("ParentImage")),
                "file_hash": sha.group(1).lower() if sha else None,
            }
        if event_id == 3:
            try:
                port = int(r.get("DestinationPort") or 0) or None
            except (TypeError, ValueError):
                port = None
            return {
                **base,
                "event_type": "network.connection",
                "user_name": _s(r.get("User")),
                "process_name": _exe(r.get("Image")),
                "src_ip": _ip(r.get("SourceIp")),
                "dst_ip": _ip(r.get("DestinationIp")),
                "dst_port": port,
                "domain": _s(r.get("DestinationHostname")),
            }
        if event_id == 22:
            return {**base, "event_type": "dns.query", "process_name": _exe(r.get("Image")), "domain": _s(r.get("QueryName"))}
        return None

    if event_id in (4624, 4625):
        user = _account(r, "TargetUserName")
        if user is None:
            return None
        return {
            **base,
            "event_type": "auth.success" if event_id == 4624 else "auth.failure",
            "outcome": "success" if event_id == 4624 else "failure",
            "user_name": user,
            "src_ip": _ip(r.get("IpAddress")),
            "message": f"Windows logon type {r.get('LogonType', '?')}" + (f" ({r['FailureReason']})" if event_id == 4625 and r.get("FailureReason") else ""),
        }
    if event_id == 4688:
        return {
            **base,
            "event_type": "process.start",
            "user_name": _account(r, "SubjectUserName"),
            "process_name": _exe(r.get("NewProcessName")),
            "command_line": _s(r.get("CommandLine"), 8192),
            "parent_process": _exe(r.get("ParentProcessName")),
        }
    if event_id == 4720:
        return {**base, "event_type": "iam.user_created", "user_name": _account(r, "SubjectUserName"), "target_user": _s(r.get("TargetUserName"), 255)}
    if event_id in (4728, 4732, 4756):
        member = _cn(r.get("MemberName")) or _s(r.get("MemberSid"))
        return {
            **base,
            "event_type": "iam.group_member_added",
            "user_name": _account(r, "SubjectUserName"),
            "target_user": member,
            "group_name": _s(r.get("TargetUserName") or r.get("GroupName")),
        }
    if event_id in (1102, 104):
        return {**base, "event_type": "log.cleared", "user_name": _account(r, "SubjectUserName") or _s(r.get("SubjectUserName"))}
    if event_id == 7036:
        name = str(r.get("param1") or r.get("ServiceName") or "")
        state = str(r.get("param2") or r.get("Message") or "").lower()
        if "stopped" not in state:
            return None
        return {**base, "event_type": "service.stopped", "process_name": _SERVICE_NAMES.get(name.lower(), name.lower())[:255] or None}
    return None


FORMATS: dict[str, Callable[[Record], dict[str, Any] | None]] = {
    "entra-signin": entra_signin,
    "entra-audit": entra_audit,
    "defender-alert": defender_alert,
    "windows-event": windows_event,
}


def map_records(fmt: str, payload: Any) -> tuple[list[EventIn], int]:
    """Translate a payload into events. Returns the events and how many records were skipped."""
    mapper = FORMATS[fmt]
    events: list[EventIn] = []
    skipped = 0
    for record in _unwrap(payload):
        try:
            mapped = mapper(record)
        except (AttributeError, KeyError, TypeError, ValueError):
            mapped = None
        if mapped is None:
            skipped += 1
            continue
        mapped = {k: v for k, v in mapped.items() if v is not None}
        try:
            events.append(EventIn.model_validate(mapped))
        except ValidationError:
            skipped += 1
    return events, skipped
