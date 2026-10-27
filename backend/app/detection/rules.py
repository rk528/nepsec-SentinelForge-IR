"""Detection rules.

Each rule documents the telemetry it needs, why it exists, how it can be
wrong, and the ATT&CK techniques it is *intended* to surface. A technique
listed here is a design intent, not proof of reliable detection everywhere;
see docs/detection-coverage.md.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import timedelta

from app.detection.base import DetectionContext, EventView, Match, Rule, is_external_ip, lower, of_type


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _hour_bucket(e: EventView) -> str:
    return e.event_time.strftime("%Y%m%d%H")


class AuthSuccessAfterFailures(Rule):
    id = "SF-AUTH-001"
    name = "Successful sign-in after repeated failures"
    description = "Five or more failed authentications for the same account from the same source address, followed by a successful authentication within ten minutes."
    severity = "high"
    confidence = "medium"
    rationale = (
        "A burst of failures that ends in success is consistent with password guessing that "
        "eventually worked. The success is what makes it urgent: failures alone are common noise."
    )
    required_telemetry = ["auth.failure", "auth.success with user_name and src_ip"]
    false_positives = [
        "A user repeatedly mistyping a recently changed password, then succeeding.",
        "Clients retrying with a cached stale credential before picking up the new one.",
        "Shared NAT egress addresses grouping several users' failures (mitigated by keying on the account).",
    ]
    attack_techniques = ["T1110", "T1110.001", "T1078"]
    lookback_minutes = 10

    THRESHOLD = 5
    WINDOW = timedelta(minutes=10)

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        by_key: dict[tuple[str, str], list[EventView]] = defaultdict(list)
        for e in of_type(events, "auth.failure", "auth.success"):
            if e.user_name and e.src_ip:
                by_key[(lower(e.user_name), e.src_ip)].append(e)

        matches: list[Match] = []
        for (user, src), items in by_key.items():
            items.sort(key=lambda e: e.event_time)
            for i, e in enumerate(items):
                if e.event_type != "auth.success":
                    continue
                failures = [f for f in items[:i] if f.event_type == "auth.failure" and e.event_time - f.event_time <= self.WINDOW]
                if len(failures) < self.THRESHOLD:
                    continue
                matches.append(
                    Match(
                        rule_id=self.id,
                        dedup_key=f"{self.id}:{user}:{src}:{_hour_bucket(e)}",
                        title=f"Sign-in succeeded for {e.user_name} after {len(failures)} failures",
                        description=(
                            f"{len(failures)} failed sign-ins for {e.user_name} from {src} in the ten minutes before a successful sign-in on {e.host or 'an unknown host'}."
                        ),
                        event_ids=[f.id for f in failures] + [e.id],
                        first_seen=failures[0].event_time,
                        last_seen=e.event_time,
                        entities={"user": e.user_name, "src_ip": src, "host": e.host},
                        evidence={
                            "failure_count": len(failures),
                            "threshold": self.THRESHOLD,
                            "window_minutes": 10,
                            "success_event_id": e.id,
                        },
                    )
                )
        return matches


class SuspiciousProcessExecution(Rule):
    id = "SF-PROC-001"
    name = "Suspicious process command line"
    description = "Process creation whose command line matches known living-off-the-land abuse patterns, or an Office application spawning a script interpreter."
    severity = "high"
    confidence = "medium"
    rationale = (
        "These built-in tools are frequently used to download payloads, run obfuscated scripts or "
        "destroy recovery data. The patterns are narrow on purpose to keep volume reviewable."
    )
    required_telemetry = ["process.start with process_name, command_line and parent_process"]
    false_positives = [
        "Administrative or software deployment scripts that use encoded PowerShell.",
        "IT tooling that uses certutil to decode certificates (not -urlcache).",
        "Office add-ins that legitimately launch helper scripts.",
    ]
    attack_techniques = ["T1059.001", "T1027", "T1105", "T1218.005", "T1218.011", "T1204.002", "T1490"]

    PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
        ("encoded_powershell", re.compile(r"powershell(\.exe)?\b.*\s-(e|en|enc|encodedcommand)\s", re.I), "high", "T1059.001"),
        ("certutil_download", re.compile(r"certutil(\.exe)?\b.*-urlcache.*http", re.I), "high", "T1105"),
        ("mshta_remote", re.compile(r"mshta(\.exe)?\b.*https?://", re.I), "high", "T1218.005"),
        ("rundll32_script", re.compile(r"rundll32(\.exe)?\b.*javascript:", re.I), "high", "T1218.011"),
        ("shadow_copy_delete", re.compile(r"vssadmin(\.exe)?\b.*delete\s+shadows", re.I), "critical", "T1490"),
    ]
    OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    SCRIPT_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "process.start"):
            cmd = e.command_line or ""
            hits = [(name, sev, tech) for name, rx, sev, tech in self.PATTERNS if rx.search(cmd + " ")]
            if lower(e.parent_process) in self.OFFICE_PARENTS and lower(e.process_name) in self.SCRIPT_CHILDREN:
                hits.append(("office_spawns_interpreter", "high", "T1204.002"))
            if not hits:
                continue
            severity = "critical" if any(h[1] == "critical" for h in hits) else "high"
            names = [h[0] for h in hits]
            matches.append(
                Match(
                    rule_id=self.id,
                    # Same command on the same host on the same day is one alert;
                    # a recurrence on a later day is a new alert.
                    dedup_key=f"{self.id}:{lower(e.host)}:{_short_hash(cmd + (e.parent_process or ''))}:{e.event_time.strftime('%Y%m%d')}",
                    title=f"Suspicious {e.process_name or 'process'} execution on {e.host or 'unknown host'}",
                    description=f"Matched pattern(s): {', '.join(names)}. Parent process: {e.parent_process or 'unknown'}.",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name, "process": e.process_name},
                    evidence={"patterns": names, "techniques": sorted({h[2] for h in hits}), "command_line": cmd[:2000]},
                    severity=severity,
                )
            )
        return matches


class PrivilegedAccountCreated(Rule):
    id = "SF-IAM-001"
    name = "New account added to a privileged group"
    description = "An account is created and added to a privileged group within 30 minutes."
    severity = "high"
    confidence = "medium"
    rationale = (
        "Creating a fresh account and immediately granting it administrative rights is a common persistence step after initial access, and is rare outside managed provisioning."
    )
    required_telemetry = ["iam.user_created with target_user", "iam.group_member_added with target_user and group_name"]
    false_positives = [
        "Planned onboarding of administrators by the identity team.",
        "Break-glass account rotation performed under a change ticket.",
    ]
    attack_techniques = ["T1136.001", "T1136.002", "T1098"]
    lookback_minutes = 30

    PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins", "sudo", "wheel"}
    WINDOW = timedelta(minutes=30)

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        created = {lower(e.target_user): e for e in of_type(events, "iam.user_created") if e.target_user}
        matches: list[Match] = []
        for add in of_type(events, "iam.group_member_added"):
            account = lower(add.target_user)
            group = lower(add.group_name)
            if group not in self.PRIVILEGED_GROUPS or account not in created:
                continue
            create = created[account]
            delta = add.event_time - create.event_time
            if delta < timedelta(0) or delta > self.WINDOW:
                continue
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{account}:{group}",
                    title=f"Account {add.target_user} created and added to {add.group_name}",
                    description=(
                        f"{create.user_name or 'An unknown actor'} created {add.target_user} on "
                        f"{create.host or 'an unknown host'}; it was added to {add.group_name} "
                        f"{int(delta.total_seconds() // 60)} minute(s) later."
                    ),
                    event_ids=[create.id, add.id],
                    first_seen=create.event_time,
                    last_seen=add.event_time,
                    entities={"user": create.user_name, "target_user": add.target_user, "group": add.group_name, "host": add.host},
                    evidence={"minutes_between": round(delta.total_seconds() / 60, 1), "group": add.group_name},
                )
            )
        return matches


class SecurityLoggingTampered(Rule):
    id = "SF-DEF-001"
    name = "Security logging cleared or stopped"
    description = "An audit log was cleared, or a security logging or telemetry service was stopped."
    severity = "high"
    confidence = "high"
    rationale = "Attackers clear or silence logs to hide activity. Legitimate log clearing is rare and should be traceable to a change record."
    required_telemetry = ["log.cleared", "service.stopped with process_name naming the service"]
    false_positives = [
        "Agent upgrades that briefly stop and restart the logging service.",
        "Lab or golden-image hosts being reset by their owners.",
    ]
    attack_techniques = ["T1070.001", "T1562.001", "T1562.002"]

    LOGGING_SERVICES = {"eventlog", "sysmon", "sysmon64", "auditd", "winlogbeat", "wazuh-agent", "osqueryd", "rsyslog"}

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "log.cleared", "service.stopped"):
            service = lower(e.process_name).removesuffix(".exe")
            if e.event_type == "service.stopped" and service not in self.LOGGING_SERVICES:
                continue
            what = "audit log cleared" if e.event_type == "log.cleared" else f"{e.process_name} service stopped"
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(e.host)}:{e.event_type}:{_hour_bucket(e)}",
                    title=f"Security logging tampered on {e.host or 'unknown host'}: {what}",
                    description=f"{what.capitalize()} by {e.user_name or 'an unknown account'}.",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name},
                    evidence={"action": e.event_type, "service": e.process_name},
                    severity="critical" if e.event_type == "log.cleared" else "high",
                )
            )
        return matches


class SuspiciousOutboundConnection(Rule):
    id = "SF-NET-001"
    name = "Suspicious outbound network connection"
    description = (
        "Outbound connection to an external address on a port commonly used by remote-access tooling, a large outbound transfer, or a destination on the organisation's watchlist."
    )
    severity = "medium"
    confidence = "low"
    rationale = (
        "Command-and-control and exfiltration often use non-standard ports or move unusual volumes of data. "
        "Watchlist matches reflect indicators an analyst already judged malicious."
    )
    required_telemetry = ["network.connection with src_ip, dst_ip, dst_port and bytes_out"]
    false_positives = [
        "Developers or administrators using non-standard ports for legitimate services.",
        "Backups or large uploads to sanctioned cloud storage.",
    ]
    attack_techniques = ["T1571", "T1041", "T1071"]

    SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 5555, 8888}
    LARGE_TRANSFER_BYTES = 50 * 1024 * 1024

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "network.connection"):
            if not is_external_ip(e.dst_ip):
                continue
            reasons: list[str] = []
            severity = self.severity
            if e.dst_port in self.SUSPICIOUS_PORTS:
                reasons.append(f"non-standard port {e.dst_port}")
            if (e.bytes_out or 0) >= self.LARGE_TRANSFER_BYTES:
                reasons.append(f"{(e.bytes_out or 0) // (1024 * 1024)} MiB sent")
            if e.dst_ip in ctx.watchlist_ips or lower(e.domain) in ctx.watchlist_domains:
                reasons.append("destination on watchlist")
                severity = "high"
            if not reasons:
                continue
            if len(reasons) > 1:
                severity = "high"
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(e.host)}:{e.dst_ip}:{e.dst_port}:{e.event_time.strftime('%Y%m%d')}",
                    title=f"Outbound connection from {e.host or e.src_ip} to {e.dst_ip}:{e.dst_port}",
                    description="Flagged because of " + ", ".join(reasons) + ".",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "domain": e.domain},
                    evidence={"reasons": reasons, "bytes_out": e.bytes_out, "dst_port": e.dst_port},
                    severity=severity,
                )
            )
        return matches


class PhishingLinkFollowed(Rule):
    id = "SF-MAIL-001"
    name = "Emailed link visited by the recipient"
    description = "A user received an email containing a link and, within 60 minutes, their host resolved or requested that link's domain."
    severity = "high"
    confidence = "medium"
    rationale = "Correlating mail delivery with a subsequent click turns a delivered phish into an observed interaction, which is when response is most valuable."
    required_telemetry = [
        "email.delivered with user_name (recipient), url and domain",
        "dns.query or proxy.request with user_name and domain",
    ]
    false_positives = [
        "Legitimate newsletters and SaaS notifications whose links users routinely follow.",
        "Mail security products that pre-fetch links (they usually originate from the gateway, not the user's host).",
    ]
    attack_techniques = ["T1566.002", "T1204.001"]
    lookback_minutes = 60

    WINDOW = timedelta(minutes=60)

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        mails = [e for e in of_type(events, "email.delivered") if e.domain and e.user_name]
        visits = [e for e in of_type(events, "dns.query", "proxy.request") if e.domain and e.user_name]
        matches: list[Match] = []
        for mail in mails:
            related = sorted(
                (
                    v
                    for v in visits
                    if lower(v.user_name) == lower(mail.user_name) and lower(v.domain) == lower(mail.domain) and timedelta(0) <= v.event_time - mail.event_time <= self.WINDOW
                ),
                key=lambda v: v.event_time,
            )
            if not related:
                continue
            first = related[0]
            minutes = round((first.event_time - mail.event_time).total_seconds() / 60, 1)
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(mail.user_name)}:{lower(mail.domain)}",
                    title=f"{mail.user_name} visited {mail.domain} from an emailed link",
                    description=(
                        f"Email from {mail.email_sender or 'an unknown sender'} with subject "
                        f'"{(mail.email_subject or "")[:120]}" was followed by a request to {mail.domain} '
                        f"from {first.host or 'an unknown host'} {minutes} minute(s) later."
                    ),
                    event_ids=[mail.id] + [v.id for v in related],
                    first_seen=mail.event_time,
                    last_seen=related[-1].event_time,
                    entities={"user": mail.user_name, "domain": mail.domain, "host": first.host, "sender": mail.email_sender},
                    evidence={"minutes_to_click": minutes, "url": mail.url, "visit_count": len(related)},
                )
            )
        return matches


ALL_RULES: list[Rule] = [
    AuthSuccessAfterFailures(),
    SuspiciousProcessExecution(),
    PrivilegedAccountCreated(),
    SecurityLoggingTampered(),
    SuspiciousOutboundConnection(),
    PhishingLinkFollowed(),
]

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}

MAX_LOOKBACK_MINUTES = max(r.lookback_minutes for r in ALL_RULES)
