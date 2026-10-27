"""FortiGate (FortiOS) logs mapped to normalised events.

FortiGate sends logs over syslog, either in its default ``key=value`` format or,
with ``set format json``, as JSON. Both arrive here as text lines, optionally
with a syslog header in front; already-parsed objects are accepted too.

Mapped:

* ``type=event subtype=vpn``: SSL-VPN login failures and established tunnels
  -> ``auth.failure`` / ``auth.success`` (feeds SF-AUTH-001).
* ``type=event subtype=system``: administrator logins -> auth events.
* ``type=traffic`` (accepted sessions) -> ``network.connection`` (SF-NET-001).
* ``type=utm subtype=dns`` -> ``dns.query``; ``subtype=webfilter`` -> ``proxy.request``
  (SF-MAIL-001 correlation).
* ``type=utm subtype=ips|virus|anomaly|app-ctrl (blocked)`` -> ``security.alert`` (SF-EXT-001).

Everything else is skipped and counted, never guessed at.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from pydantic import ValidationError

from app.schemas import EventIn

_KV = re.compile(r'(\w[\w-]*)=("(?:[^"\\]|\\.)*"|\S*)')
TRAFFIC_ACCEPTED = {"accept", "close", "timeout", "server-rst", "client-rst"}
_IPS_SEVERITY = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "informational", "information": "informational"}


def parse_line(line: str) -> dict[str, str] | None:
    """One FortiGate log line (key=value or JSON, with or without a syslog header) as a dict."""
    text = line.strip()
    if not text:
        return None
    brace = text.find("{")
    if brace != -1 and text.endswith("}"):
        try:
            obj = json.loads(text[brace:])
            if isinstance(obj, dict):
                return {str(k): "" if v is None else str(v) for k, v in obj.items()}
        except ValueError:
            pass
    # Skip a syslog header ("<189>..." or "<189>1 2026-... host - - -") up to the first key=value pair.
    start = text.find("date=")
    if start == -1:
        start = text.find("logid=")
    body = text[start:] if start > 0 else text
    pairs = {k: v[1:-1].replace('\\"', '"') if v.startswith('"') and v.endswith('"') and len(v) >= 2 else v for k, v in _KV.findall(body)}
    return pairs if "type" in pairs or "logid" in pairs else None


def _time(r: dict[str, str]) -> datetime | None:
    raw = r.get("eventtime", "")
    if raw.isdigit():
        n = int(raw)
        # FortiOS 6.2+ uses nanoseconds; older builds seconds.
        seconds = n / 1e9 if n > 1e17 else n / 1e6 if n > 1e14 else n / 1e3 if n > 1e11 else n
        return datetime.fromtimestamp(seconds, UTC)
    date, clock = r.get("date"), r.get("time")
    if not date or not clock:
        return None
    try:
        dt = datetime.fromisoformat(f"{date}T{clock}")
    except ValueError:
        return None
    tz = r.get("tz", "")
    if m := re.fullmatch(r"([+-])(\d{2}):?(\d{2})", tz.strip('"')):
        offset = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
        return dt.replace(tzinfo=timezone(offset if m.group(1) == "+" else -offset))
    return dt.replace(tzinfo=UTC)


def _s(r: dict[str, str], *keys: str, limit: int = 255) -> str | None:
    for k in keys:
        v = (r.get(k) or "").strip()
        if v and v not in ("N/A", "n/a", "-", "unknown"):
            return v[:limit]
    return None


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def map_fortigate(r: dict[str, str]) -> dict[str, Any] | None:
    when = _time(r)
    if when is None:
        return None
    kind, sub = r.get("type", "").lower(), r.get("subtype", "").lower()
    action = r.get("action", "").lower()
    device = _s(r, "devname")
    base: dict[str, Any] = {
        "event_time": when,
        "raw": {"source": "fortinet.fortigate", "logid": r.get("logid"), "type": kind, "subtype": sub, "devname": device, "action": action or None, "policyid": r.get("policyid")},
    }
    endpoint = _s(r, "srcname", "srchost")
    user = _s(r, "user", "unauthuser")

    if kind == "event" and sub == "vpn":
        if action in ("ssl-login-fail", "ssl-web-login-fail", "ssl-tunnel-login-fail"):
            return {
                **base,
                "event_type": "auth.failure",
                "outcome": "failure",
                "host": device,
                "user_name": user,
                "src_ip": _s(r, "remip"),
                "message": f"FortiGate SSL-VPN login failed: {_s(r, 'reason', 'msg') or action}",
            }
        if action == "tunnel-up" and r.get("tunneltype", "").startswith("ssl"):
            return {
                **base,
                "event_type": "auth.success",
                "outcome": "success",
                "host": device,
                "user_name": user,
                "src_ip": _s(r, "remip"),
                "message": "FortiGate SSL-VPN tunnel established",
            }
        return None

    if kind == "event" and sub == "system" and action == "login":
        status = r.get("status", "").lower()
        if status not in ("success", "failed"):
            return None
        return {
            **base,
            "event_type": "auth.success" if status == "success" else "auth.failure",
            "outcome": status if status == "success" else "failure",
            "host": device,
            "user_name": user,
            "src_ip": _s(r, "srcip"),
            "message": f"FortiGate administrator login via {_s(r, 'ui') or 'unknown interface'}",
        }

    if kind == "traffic":
        if action not in TRAFFIC_ACCEPTED:
            return None
        return {
            **base,
            "event_type": "network.connection",
            "outcome": action,
            "host": endpoint,
            "user_name": user,
            "src_ip": _s(r, "srcip"),
            "dst_ip": _s(r, "dstip"),
            "dst_port": _int(r.get("dstport")),
            "domain": _s(r, "hostname"),
            "bytes_out": _int(r.get("sentbyte")),
            "message": f"{_s(r, 'service') or 'traffic'} {_s(r, 'app') or ''}".strip(),
        }

    if kind == "utm" and sub == "dns":
        name = _s(r, "qname")
        if name is None:
            return None
        return {**base, "event_type": "dns.query", "host": endpoint, "user_name": user, "src_ip": _s(r, "srcip"), "domain": name.rstrip(".").lower(), "outcome": action or None}

    if kind == "utm" and sub == "webfilter":
        hostname = _s(r, "hostname")
        if hostname is None:
            return None
        scheme = "http" if r.get("service", "").upper() == "HTTP" else "https"
        path = _s(r, "url", limit=1900) or "/"
        return {
            **base,
            "event_type": "proxy.request",
            "outcome": action or None,
            "host": endpoint,
            "user_name": user,
            "src_ip": _s(r, "srcip"),
            "dst_ip": _s(r, "dstip"),
            "domain": hostname.lower(),
            "url": f"{scheme}://{hostname}{path if path.startswith('/') else '/' + path}"[:2048],
            "message": _s(r, "catdesc", "msg", limit=500),
        }

    if kind == "utm" and (sub in ("ips", "anomaly", "virus") or (sub == "app-ctrl" and action == "block")):
        if sub == "virus":
            severity, what = "high", f"malware {_s(r, 'virus') or 'detected'}"
        else:
            severity = _IPS_SEVERITY.get(r.get("severity", "").lower(), "medium" if sub == "anomaly" else "low")
            what = _s(r, "attack", "app", "msg") or sub
        return {
            **base,
            "event_type": "security.alert",
            "outcome": severity,
            "host": endpoint or _s(r, "srcip"),
            "user_name": user,
            "src_ip": _s(r, "srcip"),
            "dst_ip": _s(r, "dstip"),
            "dst_port": _int(r.get("dstport")),
            "message": f"FortiGate {sub.upper() if sub != 'virus' else 'antivirus'}: {what} ({action or 'logged'})"[:4000],
            "raw": {**base["raw"], "attack": r.get("attack"), "attackid": r.get("attackid"), "ref": r.get("ref"), "severity": r.get("severity")},
        }
    return None


def map_fortigate_payload(payload: Any) -> tuple[list[EventIn], int]:
    """Lines or objects from a relay batch -> events, plus the number of records skipped."""
    if isinstance(payload, dict):
        items = payload.get("logs") if isinstance(payload.get("logs"), list) else [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        return [], 0
    events: list[EventIn] = []
    skipped = 0
    for item in items:
        record = parse_line(item) if isinstance(item, str) else {str(k): "" if v is None else str(v) for k, v in item.items()} if isinstance(item, dict) else None
        mapped = map_fortigate(record) if record else None
        if mapped is None:
            skipped += 1
            continue
        try:
            events.append(EventIn.model_validate({k: v for k, v in mapped.items() if v is not None}))
        except ValidationError:
            skipped += 1
    return events, skipped
