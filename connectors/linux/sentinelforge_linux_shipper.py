#!/usr/bin/env python3
"""Ship Linux journal security events to SentinelForge IR.

Works on Ubuntu Server and Ubuntu Desktop (20.04 and later) and other systemd
distributions. Reads the systemd journal with ``journalctl -o json`` since the
last run and posts it to ``/api/v1/ingest/linux``. Python 3.8+ standard library only.

Two capture modes (``SENTINELFORGE_CAPTURE`` or ``--capture``):

* ``security`` (default): only the records SentinelForge maps (SSH, PAM sign-ins,
  sudo, account and group changes, security services stopping).
* ``all``: every journal line, plus one event per program a signed-in user starts,
  assembled from the auditd execve records that ``install.sh --capture all`` enables.

Run it from the systemd timer installed by ``install.sh``. Configuration comes from
the environment (the unit loads /etc/sentinelforge/linux-shipper.env), never from
the command line, so the ingest key stays out of process listings:

    SENTINELFORGE_URL=https://sentinelforge-api.kuinkel.com
    SENTINELFORGE_INGEST_KEY=sfk_...

The journal cursor of the last record sent is kept in the state file, so records
are never skipped: a failed post is retried from the same place on the next run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

DEFAULT_STATE = "/var/lib/sentinelforge/journal.cursor"
BATCH = 400
MAX_MESSAGE = 2000

IDENTIFIERS = {
    "sshd", "sshd-session", "sudo", "su", "login", "gdm-password", "gdm-password]", "gdm-autologin", "lightdm", "sddm",
    "polkit-1", "polkit-agent-helper-1", "cockpit", "useradd", "adduser", "usermod", "gpasswd",
}  # fmt: skip
SYSTEMD = {"systemd", "systemd-logind", "systemd-shutdown"}
_SYSTEMD_KEEP = re.compile(r"^Stopped |Reached target .*[Ss]hutdown|System is (powering down|rebooting|powering off)|system will (power ?off|reboot|halt) now", re.I)
FIELDS = ("__REALTIME_TIMESTAMP", "MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_HOSTNAME", "_BOOT_ID", "UNIT", "USER_UNIT", "_PID")
ALL_FIELDS = FIELDS + ("_UID", "PRIORITY", "_SYSTEMD_UNIT", "_TRANSPORT")
MAX_BODY = 600_000  # bytes per request; the API accepts 1 MiB
SELF_UNIT = "sentinelforge-shipper.service"
EXEC_KEY = "sf_exec"  # the audit rule key install.sh sets
AUDIT_TYPES = {"1300": "SYSCALL", "1302": "PATH", "1307": "CWD", "1309": "EXECVE", "1320": "EOE", "1327": "PROCTITLE"}
_AUDIT_KV = re.compile(r'([\w\[\]]+)=("[^"]*"|\S+)')
_AUDIT_ID = re.compile(r"audit\(([\d.]+:\d+)\)")
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg, flush=True)


def wanted(record: dict[str, Any]) -> bool:
    ident = str(record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "").lower()
    if ident in IDENTIFIERS:
        return True
    if ident in SYSTEMD:
        message = record.get("MESSAGE")
        return isinstance(message, str) and bool(_SYSTEMD_KEEP.search(message))
    return False


def slim(record: dict[str, Any], capture: str = "security") -> dict[str, Any]:
    out = {k: record[k] for k in (ALL_FIELDS if capture == "all" else FIELDS) if k in record}
    if isinstance(out.get("MESSAGE"), str) and len(out["MESSAGE"]) > MAX_MESSAGE:
        out["MESSAGE"] = out["MESSAGE"][:MAX_MESSAGE]
    if capture == "all":
        name = user_name(record.get("_UID"))
        if name:
            out["SF_USER"] = name
    return out


_USERS: dict[str, str | None] = {}


def user_name(uid: Any) -> str | None:
    key = str(uid or "").strip()
    if not key.isdigit() or key == "4294967295":  # unset login uid
        return None
    if key not in _USERS:
        try:
            import pwd  # Linux only; imported here so the tests also load the module on Windows

            _USERS[key] = pwd.getpwuid(int(key)).pw_name
        except (ImportError, KeyError, OverflowError):
            _USERS[key] = key
    return _USERS[key]


def _audit_value(value: str) -> str:
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    if _HEX.match(value):  # the kernel hex-encodes values containing spaces or special characters
        return bytes.fromhex(value).decode("utf-8", "replace")
    return value


def audit_fields(message: str) -> dict[str, str]:
    return dict(_AUDIT_KV.findall(message))


def audit_type(record: dict[str, Any]) -> str:
    name = str(record.get("_AUDIT_TYPE_NAME") or AUDIT_TYPES.get(str(record.get("_AUDIT_TYPE") or ""), ""))
    if not name and isinstance(record.get("MESSAGE"), str):
        m = re.match(r"^(?:audit: )?(?:type=)?([A-Z_]+)\b", record["MESSAGE"])
        name = m.group(1) if m else ""
    return name


def audit_id(record: dict[str, Any]) -> str | None:
    if record.get("_AUDIT_ID"):
        return str(record["_AUDIT_ID"])
    m = _AUDIT_ID.search(str(record.get("MESSAGE") or ""))
    return m.group(1) if m else None


def _argv(execve: dict[str, str]) -> list[str]:
    args: dict[int, str] = {}
    chunks: dict[int, dict[int, str]] = {}
    for k, v in execve.items():
        whole = re.fullmatch(r"a(\d+)", k)
        piece = re.fullmatch(r"a(\d+)\[(\d+)\]", k)  # long arguments arrive in pieces
        if whole:
            args[int(whole.group(1))] = _audit_value(v)
        elif piece:
            chunks.setdefault(int(piece.group(1)), {})[int(piece.group(2))] = _audit_value(v)
    for i, parts in chunks.items():
        args[i] = "".join(parts[j] for j in sorted(parts))
    return [args[i] for i in sorted(args)]


class ExecAssembler:
    """Joins the SYSCALL, EXECVE, CWD and PROCTITLE records of one audit event into one record."""

    def __init__(self) -> None:
        self.pending: dict[str, dict[str, Any]] = {}

    def feed(self, record: dict[str, Any]) -> tuple[bool, list[dict[str, Any]]]:
        """Returns (consumed, completed exec records)."""
        kind = audit_type(record)
        if str(record.get("_TRANSPORT") or "") != "audit" or kind not in AUDIT_TYPES.values():
            return False, []
        aid = audit_id(record)
        if aid is None:
            return False, []
        # The records of one audit event are adjacent, so a new id completes the earlier ones.
        done = [self._emit(k) for k in [k for k in self.pending if k != aid]]
        fields = audit_fields(str(record.get("MESSAGE") or ""))
        if kind == "SYSCALL":
            if _audit_value(fields.get("key", "")) != EXEC_KEY:
                return False, done
            self.pending[aid] = {"record": record, "SYSCALL": fields}
        elif aid in self.pending:
            if kind == "EOE":
                return True, [*done, self._emit(aid)]
            self.pending[aid].setdefault(kind, fields)
        else:
            return False, done
        return True, done

    def drain(self) -> list[dict[str, Any]]:
        return [self._emit(k) for k in list(self.pending)]

    def _emit(self, aid: str) -> dict[str, Any]:
        p = self.pending.pop(aid)
        sys_, first = p["SYSCALL"], p["record"]
        argv = _argv(p.get("EXECVE", {}))
        if not argv and "proctitle" in p.get("PROCTITLE", {}):
            argv = [a for a in _audit_value(p["PROCTITLE"]["proctitle"]).split("\x00") if a]
        exe = _audit_value(sys_.get("exe", ""))
        command = " ".join(argv) or exe
        return {
            "__REALTIME_TIMESTAMP": first.get("__REALTIME_TIMESTAMP"),
            "_HOSTNAME": first.get("_HOSTNAME"),
            "_BOOT_ID": first.get("_BOOT_ID"),
            "SYSLOG_IDENTIFIER": "sf-audit-exec",
            "MESSAGE": command[:MAX_MESSAGE],
            "SF_EXEC": {
                "audit_id": aid,
                "exe": exe,
                "argv": [a[:MAX_MESSAGE] for a in argv[:256]],
                "user": user_name(sys_.get("auid")),
                "run_as": user_name(sys_.get("uid")),
                "tty": sys_.get("tty"),
                "cwd": _audit_value(p.get("CWD", {}).get("cwd", "")) or None,
                "pid": sys_.get("pid"),
                "ppid": sys_.get("ppid"),
                "success": sys_.get("success", "yes"),
            },
        }


def journal(cursor: str | None, lookback_minutes: int, journalctl: str = "journalctl") -> Iterator[dict[str, Any]]:
    cmd = [journalctl, "-o", "json", "--no-pager", "-q"]
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["--since", f"-{lookback_minutes}min"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")  # noqa: S603 - fixed argv, no shell
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue
    _, err = proc.communicate()
    if proc.returncode not in (0, None):
        raise RuntimeError(f"journalctl failed ({proc.returncode}): {err.strip()[:300]}")


def post(url: str, key: str, records: list[dict[str, Any]], timeout: float = 30.0, capture: str = "security") -> dict[str, Any]:
    body = json.dumps({"records": records, "capture": capture}, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 - https enforced in main()
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}", "User-Agent": "SentinelForge-Linux-Shipper/1.0"},
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced in main()
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                time.sleep(int(exc.headers.get("Retry-After") or 5 * (attempt + 1)))
                continue
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            raise RuntimeError(f"API unreachable: {exc.reason}") from None
    raise RuntimeError("unreachable")


def read_cursor(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except FileNotFoundError:
        return None


def write_cursor(path: str, cursor: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(cursor)
    os.replace(tmp, path)


def run(url: str, key: str, state: str, lookback: int, dry_run: bool = False, journalctl: str = "journalctl", capture: str = "security") -> dict[str, int]:
    endpoint = url.rstrip("/") + "/api/v1/ingest/linux"
    cursor = read_cursor(state)
    totals = {"read": 0, "sent": 0, "inserted": 0, "alerts": 0}
    batch: list[dict[str, Any]] = []
    size = [0]
    last_cursor: str | None = None
    execs = ExecAssembler()

    def add(record: dict[str, Any]) -> None:
        batch.append(record)
        size[0] += len(json.dumps(record, separators=(",", ":")))
        if dry_run:
            print(json.dumps(record))
        if len(batch) >= BATCH or size[0] >= MAX_BODY:
            flush()

    def flush() -> None:
        size[0] = 0
        if batch and not dry_run:
            result = post(endpoint, key, batch, capture=capture)
            totals["inserted"] += int(result.get("inserted") or 0)
            totals["alerts"] += int(result.get("alerts_created") or 0)
        totals["sent"] += len(batch)
        batch.clear()
        # Advance only past records that were delivered (or deliberately not needed).
        if last_cursor and not dry_run:
            write_cursor(state, last_cursor)

    for record in journal(cursor, lookback, journalctl):
        totals["read"] += 1
        last_cursor = record.get("__CURSOR") or last_cursor
        if capture == "all":
            if record.get("_SYSTEMD_UNIT") == SELF_UNIT:
                continue  # our own "read N records" lines would only feed back into the next run
            consumed, done = execs.feed(record)
            for exec_record in done:
                add(exec_record)
            if not consumed:
                add(slim(record, capture))
        elif wanted(record):
            add(slim(record))
    for exec_record in execs.drain():
        add(exec_record)
    flush()
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--state", default=os.environ.get("SENTINELFORGE_STATE", DEFAULT_STATE))
    parser.add_argument("--lookback-minutes", type=int, default=60, help="history to read on the first run (default 60)")
    parser.add_argument("--dry-run", action="store_true", help="print the records that would be sent; send nothing, keep the cursor")
    parser.add_argument("--capture", choices=("security", "all"), default=os.environ.get("SENTINELFORGE_CAPTURE", "").strip() or "security")
    args = parser.parse_args()

    url = os.environ.get("SENTINELFORGE_URL", "").strip()
    key = os.environ.get("SENTINELFORGE_INGEST_KEY", "").strip()
    if not args.dry_run:
        if not key.startswith("sfk_"):
            log("Set SENTINELFORGE_INGEST_KEY to the data source ingest key (sfk_...).")
            return 2
        if not (url.startswith("https://") or re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/?$", url)):
            log("SENTINELFORGE_URL must use https.")
            return 2
    try:
        totals = run(url, key, args.state, args.lookback_minutes, args.dry_run, capture=args.capture)
    except RuntimeError as exc:
        log(f"error: {exc}")
        return 1
    log(f"read {totals['read']} journal records, sent {totals['sent']}, {totals['inserted']} new events, {totals['alerts']} alerts raised")
    return 0


if __name__ == "__main__":
    sys.exit(main())
