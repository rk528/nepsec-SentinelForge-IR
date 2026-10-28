"""Small, static MITRE ATT&CK (Enterprise) reference used by the coverage view.

Only techniques referenced by rules, plus a short list of high-value
techniques this platform has *no* telemetry for, are included. Names and
tactics follow ATT&CK Enterprise; see https://attack.mitre.org/.
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1218.005": {"name": "System Binary Proxy Execution: Mshta", "tactic": "Defense Evasion"},
    "T1218.011": {"name": "System Binary Proxy Execution: Rundll32", "tactic": "Defense Evasion"},
    "T1204.001": {"name": "User Execution: Malicious Link", "tactic": "Execution"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "Execution"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1136.001": {"name": "Create Account: Local Account", "tactic": "Persistence"},
    "T1136.002": {"name": "Create Account: Domain Account", "tactic": "Persistence"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion"},
    "T1562.002": {"name": "Impair Defenses: Disable Windows Event Logging", "tactic": "Defense Evasion"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access"},
    "T1003.002": {"name": "OS Credential Dumping: Security Account Manager", "tactic": "Credential Access"},
    "T1053.005": {"name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence"},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "Persistence"},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    # Known gaps: no rule and no telemetry collected.
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
}

KNOWN_GAPS: dict[str, str] = {
    "T1486": "No file-system write volume telemetry; only shadow-copy deletion (T1490) is covered.",
    "T1567": "Proxy logs lack destination categorisation needed to separate sanctioned cloud storage.",
}

TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
