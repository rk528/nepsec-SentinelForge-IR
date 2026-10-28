#!/usr/bin/env python3
"""Ship Linux journal security events to SentinelForge IR.

Works on Ubuntu Server and Ubuntu Desktop (20.04 and later) and other systemd
distributions. Reads the systemd journal with ``journalctl -o json`` since the
last run, keeps only the records SentinelForge maps (SSH, PAM sign-ins, sudo,
account and group changes, security services stopping) and posts them to
``/api/v1/ingest/linux``. Python 3.8+ standard library only.

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


def slim(record: dict[str, Any]) -> dict[str, Any]:
    out = {k: record[k] for k in FIELDS if k in record}
    if isinstance(out.get("MESSAGE"), str) and len(out["MESSAGE"]) > MAX_MESSAGE:
        out["MESSAGE"] = out["MESSAGE"][:MAX_MESSAGE]
    return out


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


def post(url: str, key: str, records: list[dict[str, Any]], timeout: float = 30.0) -> dict[str, Any]:
    body = json.dumps({"records": records}, separators=(",", ":")).encode("utf-8")
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


def run(url: str, key: str, state: str, lookback: int, dry_run: bool = False, journalctl: str = "journalctl") -> dict[str, int]:
    endpoint = url.rstrip("/") + "/api/v1/ingest/linux"
    cursor = read_cursor(state)
    totals = {"read": 0, "sent": 0, "inserted": 0, "alerts": 0}
    batch: list[dict[str, Any]] = []
    last_cursor: str | None = None

    def flush() -> None:
        if batch and not dry_run:
            result = post(endpoint, key, batch)
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
        if wanted(record):
            batch.append(slim(record))
            if dry_run:
                print(json.dumps(slim(record)))
        if len(batch) >= BATCH:
            flush()
    flush()
    return totals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--state", default=os.environ.get("SENTINELFORGE_STATE", DEFAULT_STATE))
    parser.add_argument("--lookback-minutes", type=int, default=60, help="history to read on the first run (default 60)")
    parser.add_argument("--dry-run", action="store_true", help="print the records that would be sent; send nothing, keep the cursor")
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
        totals = run(url, key, args.state, args.lookback_minutes, args.dry_run)
    except RuntimeError as exc:
        log(f"error: {exc}")
        return 1
    log(f"read {totals['read']} journal records, sent {totals['sent']}, {totals['inserted']} new events, {totals['alerts']} alerts raised")
    return 0


if __name__ == "__main__":
    sys.exit(main())
