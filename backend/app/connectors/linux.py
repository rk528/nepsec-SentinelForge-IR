"""Linux (Ubuntu and other systemd distributions) journal records mapped to normalised events.

Records are ``journalctl -o json`` objects as sent by ``connectors/linux/sentinelforge_linux_shipper.py``.
Mapped messages, by SYSLOG_IDENTIFIER:

* ``sshd`` / ``sshd-session``: ``Accepted ... for USER from IP`` and ``Failed ... for [invalid user] USER from IP``.
* PAM in ``gdm-password``, ``lightdm``, ``login``, ``su``, ``sudo``, ``polkit-agent-helper-1``:
  ``authentication failure`` (local and GUI sign-in failures) and ``session opened`` for
  interactive logins.
* ``sudo``: every command (``COMMAND=...``) as a process start, and ``user NOT in sudoers``.
* ``useradd``, ``usermod``, ``gpasswd``: account creation and group membership changes.
* ``systemd``: security and logging services stopping (auditd, rsyslog, journald, ...),
  except during a shutdown or reboot of the same boot.

Anything else is counted as skipped, never guessed at.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from app.schemas import EventIn

Record = dict[str, Any]

SSHD = {"sshd", "sshd-session"}
# PAM services whose sessions are interactive logins (console, GUI greeters).
INTERACTIVE_LOGIN = {"gdm-password", "gdm-autologin", "lightdm", "login", "sddm"}
PAM_AUTH = INTERACTIVE_LOGIN | {"su", "sudo", "polkit-1", "polkit-agent-helper-1", "cockpit"}
# Units whose stop is worth recording. SF-DEF-001 alerts on the logging ones.
SECURITY_UNITS = {
    "auditd",
    "rsyslog",
    "syslog-ng",
    "systemd-journald",
    "sysmon",
    "wazuh-agent",
    "osqueryd",
    "falcon-sensor",
    "mdatp",
    "ufw",
    "apparmor",
    "fail2ban",
    "clamav-daemon",
}
# Commands that change accounts; a sudo running one names the actor for the change that follows.
ACCOUNT_TOOLS = re.compile(r"(^|/)(useradd|adduser|usermod|gpasswd|groupmod|deluser|userdel)(\s|$)")

_SSH_ACCEPTED = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port \d+")
_SSH_FAILED = re.compile(r"^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port \d+")
_PAM_AUTH_FAIL = re.compile(r"pam_unix\(([\w.-]+):auth\): authentication failure;(.*)$")
_PAM_SESSION = re.compile(r"pam_unix\(([\w.-]+):session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))?(?: by ([^\s(]*))?")
_KV = re.compile(r"(\w+)=(\S*)")
_SUDO = re.compile(r"^\s*(\S+) : (.*)$")
_NEW_USER = re.compile(r"^new user: name=([^,\s]+)")
_USERMOD_ADD = re.compile(r"^add '([^']+)' to group '([^']+)'")
_GPASSWD_ADD = re.compile(r"^user (\S+) added by (\S+) to group (\S+)")
_GPASSWD_SET = re.compile(r"^members of group (\S+) set by (\S+) to (\S*)")
_SHUTDOWN = re.compile(r"Reached target .*[Ss]hutdown|System is (powering down|rebooting|powering off)|system will (power ?off|reboot|halt) now", re.I)


def _message(r: Record) -> str:
    value = r.get("MESSAGE")
    if isinstance(value, list):  # journald exports non-UTF-8 messages as byte arrays
        try:
            value = bytes(v for v in value if isinstance(v, int) and 0 <= v < 256).decode("utf-8", "replace")
        except ValueError:
            return ""
    return value.strip() if isinstance(value, str) else ""


def _time(r: Record) -> datetime | None:
    raw = r.get("__REALTIME_TIMESTAMP")
    try:
        micros = int(str(raw))
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(micros / 1_000_000, UTC)


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if v.startswith("::ffff:"):
        v = v[7:]
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None  # PAM rhost can be a hostname or a tty; only addresses are kept
    return None if v in ("127.0.0.1", "::1") else v


def _user(value: str | None) -> str | None:
    v = (value or "").strip()
    return v[:255] if v and v not in ("-", "(unknown)") else None


def _identifier(r: Record) -> str:
    ident = str(r.get("SYSLOG_IDENTIFIER") or r.get("_COMM") or "")
    return ident.rstrip("]").strip().lower()  # GDM logs as "gdm-password]"


def _service_unit(r: Record, message: str) -> str | None:
    if not message.startswith("Stopped "):
        return None
    unit = str(r.get("UNIT") or r.get("USER_UNIT") or "")
    if not unit:
        m = re.match(r"Stopped (\S+)\.service\b", message)
        unit = m.group(1) if m else ""
    name = unit.removesuffix(".service").lower()
    return name if name in SECURITY_UNITS else None


def map_record(r: Record, *, actor: str | None = None) -> list[dict[str, Any]]:
    """One journal record -> zero or more normalised events (``gpasswd -M`` can add several members)."""
    when = _time(r)
    message = _message(r)
    if when is None or not message:
        return []
    ident = _identifier(r)
    host = str(r.get("_HOSTNAME") or "").strip().lower()[:255] or None
    base: dict[str, Any] = {"event_time": when, "host": host, "message": message[:4000], "raw": {"source": "linux.journald", "identifier": ident}}
    if r.get("_BOOT_ID"):
        base["raw"]["boot_id"] = str(r["_BOOT_ID"])[:64]

    if ident in SSHD:
        if m := _SSH_ACCEPTED.match(message):
            return [
                {
                    **base,
                    "event_type": "auth.success",
                    "outcome": "success",
                    "user_name": _user(m.group(2)),
                    "src_ip": _ip(m.group(3)),
                    "raw": {**base["raw"], "method": m.group(1), "logon": "ssh"},
                }
            ]
        if m := _SSH_FAILED.match(message):
            return [
                {
                    **base,
                    "event_type": "auth.failure",
                    "outcome": "failure",
                    "user_name": _user(m.group(2)),
                    "src_ip": _ip(m.group(3)),
                    "raw": {**base["raw"], "method": m.group(1), "logon": "ssh"},
                }
            ]
        return []  # PAM lines from sshd duplicate the two above

    if ident in PAM_AUTH and (m := _PAM_AUTH_FAIL.search(message)):
        fields = dict(_KV.findall(m.group(2)))
        user = _user(fields.get("user")) or _user(fields.get("ruser"))
        return [
            {
                **base,
                "event_type": "auth.failure",
                "outcome": "failure",
                "user_name": user,
                "src_ip": _ip(fields.get("rhost")),
                "raw": {**base["raw"], "pam_service": m.group(1), "tty": fields.get("tty") or None},
            }
        ]
    if ident in PAM_AUTH and (m := _PAM_SESSION.search(message)):
        service, user, by = m.group(1), m.group(2), m.group(3)
        if service in INTERACTIVE_LOGIN:
            return [{**base, "event_type": "auth.success", "outcome": "success", "user_name": _user(user), "raw": {**base["raw"], "pam_service": service, "logon": "interactive"}}]
        if service == "su":
            return [
                {
                    **base,
                    "event_type": "auth.success",
                    "outcome": "success",
                    "user_name": _user(by),
                    "target_user": _user(user),
                    "raw": {**base["raw"], "pam_service": "su", "logon": "su"},
                }
            ]
        return []

    if ident == "sudo" and (m := _SUDO.match(message)):
        user = _user(m.group(1))
        fields = {k.strip(): v.strip() for k, _, v in (part.partition("=") for part in m.group(2).split(" ; ")) if k}
        command = fields.get("COMMAND")
        if "NOT in sudoers" in m.group(2) or "command not allowed" in m.group(2):
            return [
                {
                    **base,
                    "event_type": "auth.failure",
                    "outcome": "denied",
                    "user_name": user,
                    "target_user": _user(fields.get("USER")),
                    "raw": {**base["raw"], "pam_service": "sudo"},
                }
            ]
        if command:
            program = command.split(" ", 1)[0]
            return [
                {
                    **base,
                    "event_type": "process.start",
                    "user_name": user,
                    "target_user": _user(fields.get("USER")),
                    "process_name": posixpath.basename(program)[:255] or None,
                    "command_line": command[:8192],
                    "parent_process": "sudo",
                    "raw": {**base["raw"], "tty": fields.get("TTY"), "cwd": fields.get("PWD")},
                }
            ]
        return []

    if ident in ("useradd", "adduser") and (m := _NEW_USER.match(message)):
        return [{**base, "event_type": "iam.user_created", "user_name": actor, "target_user": _user(m.group(1))}]
    if ident == "usermod" and (m := _USERMOD_ADD.match(message)):
        return [{**base, "event_type": "iam.group_member_added", "user_name": actor, "target_user": _user(m.group(1)), "group_name": m.group(2)[:255]}]
    if ident == "gpasswd":
        if m := _GPASSWD_ADD.match(message):
            return [{**base, "event_type": "iam.group_member_added", "user_name": actor or _user(m.group(2)), "target_user": _user(m.group(1)), "group_name": m.group(3)[:255]}]
        if m := _GPASSWD_SET.match(message):
            members = [x for x in m.group(3).split(",") if x]
            return [
                {**base, "event_type": "iam.group_member_added", "user_name": actor or _user(m.group(2)), "target_user": _user(x), "group_name": m.group(1)[:255]} for x in members
            ]
        return []

    if ident == "systemd" and (unit := _service_unit(r, message)):
        return [{**base, "event_type": "service.stopped", "process_name": unit}]
    return []


def _records(payload: Any) -> list[Record]:
    if isinstance(payload, dict):
        items = payload.get("records") if isinstance(payload.get("records"), list) else [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        return []
    return [r for r in items if isinstance(r, dict)]


def _shutdown_boots(records: Iterable[Record]) -> set[str]:
    return {str(r.get("_BOOT_ID")) for r in records if r.get("_BOOT_ID") and _identifier(r) in ("systemd", "systemd-logind", "systemd-shutdown") and _SHUTDOWN.search(_message(r))}


def map_linux_payload(payload: Any) -> tuple[list[EventIn], int]:
    """Journal records from a shipper batch -> events, plus the number of records skipped."""
    records = _records(payload)
    # Every service stops when the machine shuts down; those stops are not tampering.
    stopping = _shutdown_boots(records)
    # Last sudo user per host who ran an account tool, to name the actor of useradd/usermod.
    recent_admin: dict[str | None, tuple[datetime, str]] = {}
    events: list[EventIn] = []
    skipped = 0
    for r in sorted(records, key=lambda x: str(x.get("__REALTIME_TIMESTAMP") or "").zfill(20)):
        host = str(r.get("_HOSTNAME") or "").strip().lower() or None
        when = _time(r)
        actor = None
        if when and host in recent_admin and when - recent_admin[host][0] <= timedelta(minutes=2):
            actor = recent_admin[host][1]
        try:
            mapped = map_record(r, actor=actor)
        except (AttributeError, KeyError, TypeError, ValueError):
            mapped = []
        mapped = [m for m in mapped if not (m["event_type"] == "service.stopped" and m["raw"].get("boot_id") in stopping)]
        if not mapped:
            skipped += 1
            continue
        for m in mapped:
            if m["event_type"] == "process.start" and m.get("user_name") and ACCOUNT_TOOLS.search(m.get("command_line") or ""):
                recent_admin[host] = (m["event_time"], m["user_name"])
            try:
                events.append(EventIn.model_validate({k: v for k, v in m.items() if v is not None}))
            except ValidationError:
                skipped += 1
    return events, skipped
