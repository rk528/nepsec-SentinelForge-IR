"""FortiGate log ingestion: FortiOS key=value and JSON syslog lines (synthetic values)."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.connectors.fortigate import map_fortigate_payload, parse_line
from tests.helpers import create_source


def _ns(minutes: float) -> int:
    return int((datetime.now(UTC) - timedelta(minutes=30) + timedelta(minutes=minutes)).timestamp() * 1e9)


HDR = '<185>date=2026-10-27 time=10:01:02 devname="FGT60F-HQ" devid="FGT60FTK2209XXXX" tz="+0545" vd="root"'


def vpn_fail(minutes: float) -> str:
    return (
        f'{HDR} eventtime={_ns(minutes)} logid="0101039426" type="event" subtype="vpn" level="alert" logdesc="SSL VPN login fail" '
        'action="ssl-login-fail" tunneltype="ssl-web" remip=203.0.113.50 user="j.alvarez" group="N/A" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"'
    )


def vpn_up(minutes: float) -> str:
    return (
        f'{HDR} eventtime={_ns(minutes)} logid="0101039947" type="event" subtype="vpn" logdesc="SSL VPN tunnel up" '
        'action="tunnel-up" tunneltype="ssl-tunnel" remip=203.0.113.50 user="j.alvarez" msg="SSL tunnel established"'
    )


def _post(api, key: str, logs: list) -> dict:
    r = api.client.post("/api/v1/ingest/fortigate", json={"logs": logs}, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200, r.text
    return r.json()


def _rules(api) -> set[str]:
    return {a["rule_id"] for a in api.get("/api/v1/alerts", params={"page_size": 100}).json()["items"]}


def test_ssl_vpn_password_guessing_raises_alert(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "FortiGate HQ")
    body = _post(admin, key, [vpn_fail(i * 0.4) for i in range(6)] + [vpn_up(4)])
    assert body["inserted"] == 7 and body["skipped"] == 0 and body["alerts_created"] == 1
    assert "SF-AUTH-001" in _rules(admin)


def test_traffic_dns_webfilter_and_ips(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "FortiGate HQ")
    lines = [
        f'{HDR} eventtime={_ns(1)} logid="0000000013" type="traffic" subtype="forward" srcip=10.20.4.17 srcname="FIN-WS-014" srcport=50432 dstip=198.51.100.23 dstport=4444 proto=6 action="close" policyid=5 service="tcp/4444" sentbyte=18000 rcvdbyte=2000',
        f'{HDR} eventtime={_ns(1)} logid="0000000013" type="traffic" subtype="forward" srcip=10.20.4.17 dstip=198.51.100.24 dstport=443 action="deny" policyid=9',
        f'{HDR} eventtime={_ns(2)} logid="1501054802" type="utm" subtype="dns" srcip=10.20.4.17 srcname="FIN-WS-014" qname="invoice-portal.example" action="pass"',
        f'{HDR} eventtime={_ns(3)} logid="0316013056" type="utm" subtype="webfilter" srcip=10.20.4.17 srcname="FIN-WS-014" hostname="invoice-portal.example" url="/view?id=1" service="HTTPS" action="passthrough" user="j.alvarez" catdesc="Phishing"',
        f'{HDR} eventtime={_ns(4)} logid="0419016384" type="utm" subtype="ips" severity="critical" srcip=203.0.113.66 dstip=10.20.1.5 dstport=443 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" attackid=51006',
        f'{HDR} eventtime={_ns(5)} logid="0100032001" type="event" subtype="system" logdesc="Configuration changed" action="Edit" user="admin"',
    ]  # fmt: skip
    body = _post(admin, key, lines)
    assert body["inserted"] == 4 and body["skipped"] == 2  # denied session and config change are skipped
    rules = _rules(admin)
    assert {"SF-NET-001", "SF-EXT-001"} <= rules
    events = admin.get("/api/v1/events", params={"page_size": 50}).json()["items"]
    proxy = next(e for e in events if e["event_type"] == "proxy.request")
    assert proxy["url"] == "https://invoice-portal.example/view?id=1" and proxy["host"] == "FIN-WS-014"


def test_json_format_and_admin_login() -> None:
    record = {
        "date": "2026-10-27", "time": "09:15:00", "tz": "+0545", "devname": "FGT60F-HQ", "logid": "0100032002",
        "type": "event", "subtype": "system", "logdesc": "Admin login failed", "user": "admin",
        "ui": "https(198.51.100.9)", "srcip": "198.51.100.9", "action": "login", "status": "failed",
    }  # fmt: skip
    line = "<189>1 2026-10-27T09:15:00+05:45 FGT60F-HQ - - - " + json.dumps(record)
    events, skipped = map_fortigate_payload({"logs": [line]})
    assert skipped == 0
    ev = events[0]
    assert ev.event_type == "auth.failure" and ev.user_name == "admin" and ev.src_ip == "198.51.100.9"
    assert ev.event_time == datetime(2026, 10, 27, 3, 30, tzinfo=UTC)  # +05:45 converted to UTC


def test_parser_handles_quotes_and_garbage() -> None:
    parsed = parse_line('date=2026-10-27 time=10:00:00 type="utm" subtype="ips" attack="A \\"quoted\\" name" msg="x=y inside"')
    assert parsed and parsed["attack"] == 'A "quoted" name' and parsed["msg"] == "x=y inside"
    assert parse_line("") is None and parse_line("not a fortigate log") is None
    events, skipped = map_fortigate_payload({"logs": ["junk", 5, None, {"type": "traffic"}]})
    assert events == [] and skipped == 4


def test_fortigate_ingest_requires_key(app) -> None:
    from fastapi.testclient import TestClient

    assert TestClient(app).post("/api/v1/ingest/fortigate", json={"logs": [vpn_fail(1)]}).status_code == 401


def _relay():
    path = Path(__file__).resolve().parents[2] / "connectors" / "fortigate" / "fortigate_relay.py"
    spec = importlib.util.spec_from_file_location("fortigate_relay", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def test_relay_traffic_filter() -> None:
    relay = _relay()
    base = 'date=2026-10-27 time=10:00:00 type="traffic" subtype="forward" srcip=10.20.4.17'
    assert relay.wanted(f'{base} dstip=198.51.100.23 dstport=4444 action="close" sentbyte=900', "interesting")
    assert relay.wanted(f'{base} dstip=198.51.100.23 dstport=443 action="close" sentbyte=52428800', "interesting")
    assert not relay.wanted(f'{base} dstip=198.51.100.23 dstport=443 action="close" sentbyte=900', "interesting")
    assert not relay.wanted(f'{base} dstip=10.20.9.5 dstport=4444 action="close" sentbyte=900', "interesting")  # internal
    assert not relay.wanted(f'{base} dstip=198.51.100.23 dstport=4444 action="deny"', "interesting")
    assert relay.wanted('date=2026-10-27 time=10:00:00 type="event" subtype="vpn" action="ssl-login-fail"', "none")
    assert relay.wanted(f'{base} dstip=198.51.100.23 dstport=443 action="close"', "all")
