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

from app.detection.base import DetectionContext, EventView, Match, Rule, is_external_ip, lower, of_type, raw_str


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

    PRIVILEGED_GROUPS = {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "sudo",
        "wheel",
        # Entra ID directory roles
        "global administrator",
        "privileged role administrator",
        "security administrator",
        "user administrator",
        "exchange administrator",
        "application administrator",
        "privileged authentication administrator",
    }
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


class MicrosoftSecurityAlert(Rule):
    id = "SF-EXT-001"
    name = "Security product alert (Microsoft Defender, FortiGate)"
    description = "A medium or high severity alert raised by Microsoft Defender XDR, Defender for Cloud, Entra ID Protection, or FortiGate IPS, antivirus and anomaly detection."
    severity = "medium"
    confidence = "medium"
    rationale = (
        "Vendor detections see telemetry this platform does not, such as endpoint memory, mailbox and identity risk signals or packet payloads inspected by the firewall. "
        "Promoting them into the same queue lets analysts correlate them with local detections and run the incident workflow on them."
    )
    required_telemetry = ["security.alert from the Microsoft Graph security API or FortiGate UTM logs, severity in outcome"]
    false_positives = [
        "Whatever the vendor's detection itself gets wrong; this rule adds no judgement of its own.",
        "Alerts already resolved in the vendor console before they were forwarded.",
        "IPS signatures that match scanning traffic which the firewall already blocked.",
    ]
    # Each alert carries its own techniques (raw.mitreTechniques); the rule has none of its own.
    attack_techniques: list[str] = []
    external_attack_mapping = True

    SEVERITIES = {"high": "high", "medium": "medium"}

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "security.alert"):
            severity = self.SEVERITIES.get(lower(e.outcome))
            if severity is None:
                continue
            title = e.message or "Microsoft security alert"
            matches.append(
                Match(
                    rule_id=self.id,
                    # Re-forwarding the same alert (e.g. after a status change) updates one alert, not several.
                    dedup_key=f"{self.id}:{_short_hash(f'{title}|{lower(e.host)}|{lower(e.user_name)}')}:{e.event_time.strftime('%Y%m%d')}",
                    title=title[:300],
                    description=f"Forwarded from a security product for {e.host or e.user_name or e.src_ip or 'an unnamed entity'}. See the event for the vendor's details.",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name, "src_ip": e.src_ip},
                    evidence={"microsoft_severity": e.outcome, "portal_url": e.url},
                    severity=severity,
                )
            )
        return matches


class CredentialDumping(Rule):
    id = "SF-CRED-001"
    name = "LSASS memory access or credential store dump"
    description = (
        "A process opens lsass.exe with memory-read rights, or a command line dumps LSASS (comsvcs.dll MiniDump, procdump) or saves the SAM, SECURITY or SYSTEM registry hives."
    )
    severity = "critical"
    confidence = "medium"
    rationale = (
        "Reading LSASS memory or copying the local credential hives yields password hashes and Kerberos tickets for every account that signed in to the host. "
        "Outside security products and a few system processes, nothing needs that access, and its use usually precedes lateral movement."
    )
    required_telemetry = [
        "process.access (Sysmon event 10) with process_name, raw.target_image and raw.granted_access",
        "process.start with command_line",
    ]
    false_positives = [
        "EDR, antivirus and backup agents not on the allowlist that inspect LSASS.",
        "Administrators collecting an LSASS dump for Microsoft support under a change ticket.",
        "Sysmon configurations that log every LSASS handle produce volume; the rule only fires on memory-read rights.",
    ]
    attack_techniques = ["T1003", "T1003.001", "T1003.002"]

    # PROCESS_VM_READ. Handles without it (query information only) are routine.
    VM_READ = 0x0010
    # Image names that legitimately read LSASS memory. Matched by name only, see the known limitation.
    ALLOWED_SOURCES = {"msmpeng.exe", "mssense.exe", "csrss.exe", "wininit.exe", "lsm.exe", "services.exe", "wmiprvse.exe", "taskmgr.exe", "lsass.exe"}
    PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
        ("comsvcs_minidump", re.compile(r"comsvcs(\.dll)?[\s,].*minidump", re.I), "T1003.001"),
        ("procdump_lsass", re.compile(r"procdump(64)?(\.exe)?\b.*\s-ma?\b.*lsass", re.I), "T1003.001"),
        ("registry_hive_save", re.compile(r"reg(\.exe)?\s+save\s+(hklm|hkey_local_machine)\\(sam|security|system)\b", re.I), "T1003.002"),
    ]

    @classmethod
    def _access_mask(cls, value: str) -> int | None:
        try:
            return int(value, 16) if value.startswith("0x") else int(value)
        except ValueError:
            return None

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "process.access", "process.start"):
            if e.event_type == "process.access":
                target = raw_str(e, "target_image").replace("/", "\\").rsplit("\\", 1)[-1]
                mask = self._access_mask(raw_str(e, "granted_access"))
                if target != "lsass.exe" or mask is None or not mask & self.VM_READ or lower(e.process_name) in self.ALLOWED_SOURCES:
                    continue
                hits = [("lsass_memory_read", "T1003.001")]
                key = f"{lower(e.process_name)}:{e.event_time.strftime('%Y%m%d')}"
                evidence: dict[str, object] = {"granted_access": raw_str(e, "granted_access"), "source_image": e.raw.get("source_image")}
            else:
                cmd = e.command_line or ""
                hits = [(name, tech) for name, rx, tech in self.PATTERNS if rx.search(cmd)]
                if not hits:
                    continue
                key = f"{_short_hash(cmd)}:{e.event_time.strftime('%Y%m%d')}"
                evidence = {"command_line": cmd[:2000]}
            names = [h[0] for h in hits]
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(e.host)}:{key}",
                    title=f"Credential dumping on {e.host or 'unknown host'} by {e.process_name or 'an unknown process'}",
                    description=f"Matched: {', '.join(names)}. Account: {e.user_name or 'unknown'}.",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name, "process": e.process_name},
                    evidence={"patterns": names, "techniques": sorted({h[1] for h in hits}), **evidence},
                )
            )
        return matches


# Shared by the persistence rules: what makes an autostart entry worth a look.
_INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe"}
_USER_WRITABLE = re.compile(r"\\(appdata|temp|tmp|users\\public|programdata|downloads|perflogs)\\|%(appdata|localappdata|temp|tmp|public|programdata)%", re.I)
_INTERPRETER_IN_CMD = re.compile(r"(^|[\\\s\"'])(" + "|".join(re.escape(n.removesuffix(".exe")) for n in sorted(_INTERPRETERS)) + r")(\.exe)?\b", re.I)


def _autostart_reasons(payload: str) -> list[str]:
    reasons = []
    if _INTERPRETER_IN_CMD.search(payload):
        reasons.append("runs a script interpreter or system proxy binary")
    if _USER_WRITABLE.search(payload):
        reasons.append("runs from a user-writable directory")
    if re.search(r"https?://", payload, re.I):
        reasons.append("references a URL")
    return reasons


class SuspiciousScheduledTask(Rule):
    id = "SF-PERS-001"
    name = "Scheduled task that runs a script or a user-writable binary"
    description = (
        "A scheduled task is registered (Security event 4698, or schtasks /create in a command line) whose action runs a script interpreter, "
        "a system proxy binary, a URL, or a program in a user-writable directory."
    )
    severity = "high"
    confidence = "medium"
    rationale = (
        "Scheduled tasks give attackers persistence and SYSTEM-level execution. Software installers register tasks too, but they almost always point at signed "
        "binaries under Program Files; tasks that launch PowerShell or a file in AppData or Temp are the pattern seen in intrusions."
    )
    required_telemetry = [
        "task.created (Security event 4698, requires 'Audit Other Object Access Events') with command_line holding the task action",
        "process.start with command_line, for schtasks.exe",
    ]
    false_positives = [
        "Per-user updaters installed under AppData (OneDrive, Teams, browser updaters).",
        "Administrative maintenance tasks that are PowerShell scripts, including this platform's own Windows shipper (one alert per host when it is installed).",
    ]
    attack_techniques = ["T1053.005"]

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "task.created", "process.start"):
            if e.event_type == "process.start":
                if lower(e.process_name) != "schtasks.exe" or not re.search(r"[/-]create\b", e.command_line or "", re.I):
                    continue
                task = raw_str(e, "task_name") or "(from schtasks command line)"
            else:
                task = raw_str(e, "task_name") or "unnamed task"
            payload = e.command_line or ""
            reasons = _autostart_reasons(payload)
            if not reasons:
                continue
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(e.host)}:{_short_hash(payload)}",
                    title=f"Suspicious scheduled task on {e.host or 'unknown host'}",
                    description=f"Task {task} created by {e.user_name or 'an unknown account'}: " + "; ".join(reasons) + ".",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name},
                    evidence={"task_name": task, "action": payload[:2000], "reasons": reasons, "source_event": e.event_type},
                )
            )
        return matches


class RunKeyPersistence(Rule):
    id = "SF-PERS-002"
    name = "Registry Run key set to a script or a user-writable binary"
    description = (
        "A value under a Run or RunOnce key is written (Sysmon event 13, or reg add in a command line) that launches a script interpreter, a system proxy binary, "
        "a URL, or a program in a user-writable directory."
    )
    severity = "high"
    confidence = "medium"
    rationale = (
        "Run keys start a program at every logon and are the simplest persistence mechanism on Windows. Installers write them too, so the rule only fires on payloads "
        "that look like a launcher rather than an installed application."
    )
    required_telemetry = [
        "registry.set (Sysmon event 13) with raw.target_object and command_line holding the value data",
        "process.start with command_line, for reg.exe",
    ]
    false_positives = [
        "Per-user applications installed under AppData that start at logon (chat clients, sync tools).",
        "Login scripts deployed by IT that call PowerShell.",
    ]
    attack_techniques = ["T1547.001"]

    RUN_KEY = re.compile(r"\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run(once)?(ex)?(\\|\s|$)", re.I)

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        matches: list[Match] = []
        for e in of_type(events, "registry.set", "process.start"):
            if e.event_type == "registry.set":
                key = raw_str(e, "target_object")
                if not self.RUN_KEY.search(key):
                    continue
                payload = e.command_line or ""
                writer_reasons = [f"written by {e.process_name}"] if lower(e.process_name) in _INTERPRETERS else []
            else:
                cmd = e.command_line or ""
                if lower(e.process_name) != "reg.exe" or not re.search(r"\badd\b", cmd, re.I) or not self.RUN_KEY.search(cmd.replace('"', "")):
                    continue
                key, payload, writer_reasons = "(from reg add command line)", cmd, []
            reasons = _autostart_reasons(payload) + writer_reasons
            if not reasons:
                continue
            matches.append(
                Match(
                    rule_id=self.id,
                    dedup_key=f"{self.id}:{lower(e.host)}:{_short_hash(key + payload)}",
                    title=f"Run key persistence on {e.host or 'unknown host'}",
                    description=f"Autostart value written by {e.process_name or 'an unknown process'} ({e.user_name or 'unknown account'}): " + "; ".join(reasons) + ".",
                    event_ids=[e.id],
                    first_seen=e.event_time,
                    last_seen=e.event_time,
                    entities={"host": e.host, "user": e.user_name, "process": e.process_name},
                    evidence={"registry_key": key, "value": payload[:2000], "reasons": reasons},
                )
            )
        return matches


class SuspiciousRdpLogon(Rule):
    id = "SF-LAT-001"
    name = "RDP logon from the internet or RDP fan-out"
    description = "A Remote Desktop logon (Windows logon type 10) from an external address, or one account opening RDP sessions on three or more hosts within 30 minutes."
    severity = "high"
    confidence = "medium"
    rationale = (
        "RDP exposed to the internet is a leading ransomware entry point, so any successful external RDP logon deserves review. Inside the network, one account hopping "
        "across several hosts in a short window is how operators move laterally with stolen credentials."
    )
    required_telemetry = ["auth.success (Security event 4624) with host, user_name, src_ip and raw.logon_type"]
    false_positives = [
        "Administrators working through several servers in a maintenance window.",
        "RDP published through a gateway or VPN that preserves the external client address.",
    ]
    attack_techniques = ["T1021.001", "T1133"]
    lookback_minutes = 30

    REMOTE_INTERACTIVE = "10"
    FANOUT_HOSTS = 3
    WINDOW = timedelta(minutes=30)

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        rdp = sorted(
            (e for e in of_type(events, "auth.success") if raw_str(e, "logon_type") == self.REMOTE_INTERACTIVE and e.user_name),
            key=lambda e: e.event_time,
        )
        matches: list[Match] = []
        for e in rdp:
            if is_external_ip(e.src_ip):
                matches.append(
                    Match(
                        rule_id=self.id,
                        dedup_key=f"{self.id}:external:{lower(e.host)}:{lower(e.user_name)}:{e.src_ip}:{e.event_time.strftime('%Y%m%d')}",
                        title=f"RDP logon to {e.host or 'unknown host'} from external address {e.src_ip}",
                        description=f"{e.user_name} signed in over Remote Desktop from {e.src_ip}, which is not an internal address.",
                        event_ids=[e.id],
                        first_seen=e.event_time,
                        last_seen=e.event_time,
                        entities={"host": e.host, "user": e.user_name, "src_ip": e.src_ip},
                        evidence={"trigger": "external_source", "logon_type": 10},
                    )
                )

        by_user: dict[str, list[EventView]] = defaultdict(list)
        for e in rdp:
            by_user[lower(e.user_name)].append(e)
        for user, items in by_user.items():
            quiet_until = None
            for i, last in enumerate(items):
                if quiet_until is not None and last.event_time < quiet_until:
                    continue
                window = [x for x in items[: i + 1] if last.event_time - x.event_time <= self.WINDOW]
                hosts = sorted({lower(x.host) for x in window if x.host})
                if len(hosts) < self.FANOUT_HOSTS:
                    continue
                matches.append(
                    Match(
                        rule_id=self.id,
                        dedup_key=f"{self.id}:fanout:{user}:{_hour_bucket(window[0])}",
                        title=f"{last.user_name} opened RDP sessions on {len(hosts)} hosts in 30 minutes",
                        description=f"Remote Desktop logons for {last.user_name} on {', '.join(hosts)}.",
                        event_ids=[x.id for x in window],
                        first_seen=window[0].event_time,
                        last_seen=last.event_time,
                        entities={"user": last.user_name, "host": last.host, "src_ip": last.src_ip},
                        evidence={"trigger": "fan_out", "hosts": hosts, "threshold": self.FANOUT_HOSTS, "window_minutes": 30},
                    )
                )
                # One alert per burst: the hops that follow belong to the same activity.
                quiet_until = last.event_time + self.WINDOW
        return matches


ALL_RULES: list[Rule] = [
    AuthSuccessAfterFailures(),
    SuspiciousProcessExecution(),
    PrivilegedAccountCreated(),
    SecurityLoggingTampered(),
    SuspiciousOutboundConnection(),
    PhishingLinkFollowed(),
    MicrosoftSecurityAlert(),
    CredentialDumping(),
    SuspiciousScheduledTask(),
    RunKeyPersistence(),
    SuspiciousRdpLogon(),
]

RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}

MAX_LOOKBACK_MINUTES = max(r.lookback_minutes for r in ALL_RULES)
