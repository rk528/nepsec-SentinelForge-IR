#!/usr/bin/env python3
"""Ship Microsoft Entra ID and Defender logs from Microsoft Graph to SentinelForge IR.

Pulls three streams with an app registration (client credentials) and posts them,
unchanged, to SentinelForge's Microsoft ingest endpoint, which maps them:

    entra-signin    GET /auditLogs/signIns           AuditLog.Read.All (needs Entra ID P1/P2)
    entra-audit     GET /auditLogs/directoryAudits   AuditLog.Read.All
    defender-alert  GET /security/alerts_v2          SecurityAlert.Read.All

Configuration comes only from environment variables, so secrets never land in
shell history or this file:

    MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET
    SENTINELFORGE_URL         e.g. https://sentinelforge-api.kuinkel.com
    SENTINELFORGE_INGEST_KEY  sfk_... from Settings -> Data sources

Usage:
    python ship_graph_logs.py                 # one pass (schedule it every 5 minutes)
    python ship_graph_logs.py --loop 300      # keep running, one pass every 300 s
    python ship_graph_logs.py --streams entra-signin,defender-alert

Standard library only. Re-sending a record is harmless: SentinelForge de-duplicates.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

GRAPH = "https://graph.microsoft.com/v1.0"
STREAMS = {
    "entra-signin": ("/auditLogs/signIns", "createdDateTime"),
    "entra-audit": ("/auditLogs/directoryAudits", "activityDateTime"),
    "defender-alert": ("/security/alerts_v2", "lastUpdateDateTime"),
}
BATCH = 100  # keeps each request well under the 1 MiB ingest limit
USER_AGENT = "SentinelForge-GraphShipper/1.0"


def log(msg: str) -> None:
    print(f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}", flush=True)


def env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Set the {name} environment variable")
    return value


def request(url: str, *, data: bytes | None = None, headers: dict[str, str] | None = None, method: str | None = None) -> Any:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})}, method=method)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503, 504) and attempt < 4:
                wait = int(exc.headers.get("Retry-After") or 2 ** (attempt + 1))
                log(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}; retrying in {wait}s")
                time.sleep(min(wait, 120))
                continue
            detail = exc.read()[:300].decode("utf-8", "replace")
            raise RuntimeError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}{urllib.parse.urlsplit(url).path}: {detail}") from None
        except urllib.error.URLError as exc:
            if attempt < 4:
                time.sleep(2 ** (attempt + 1))
                continue
            raise RuntimeError(f"Cannot reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}") from None
    raise RuntimeError("unreachable")


def graph_token(tenant: str, client_id: str, secret: str) -> str:
    form = urllib.parse.urlencode(
        {"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"}
    ).encode()
    body = request(f"https://login.microsoftonline.com/{urllib.parse.quote(tenant)}/oauth2/v2.0/token", data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
    return body["access_token"]


def fetch(token: str, path: str, time_field: str, since: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"$filter": f"{time_field} ge {since}", "$top": "500"})
    url: str | None = f"{GRAPH}{path}?{query}"
    records: list[dict[str, Any]] = []
    while url:
        page = request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        records.extend(page.get("value") or [])
        url = page.get("@odata.nextLink")
    return records


def ship(base: str, key: str, fmt: str, records: list[dict[str, Any]]) -> dict[str, int]:
    totals = {"inserted": 0, "duplicates": 0, "skipped": 0, "alerts_created": 0}
    for i in range(0, len(records), BATCH):
        body = json.dumps({"value": records[i : i + BATCH]}).encode("utf-8")
        result = request(
            f"{base}/api/v1/ingest/microsoft/{fmt}",
            data=body,
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            method="POST",
        )
        for k in totals:
            totals[k] += int(result.get(k, 0))
    return totals


def run_once(state_file: Path, streams: list[str], lookback_minutes: int) -> bool:
    tenant, client_id, secret = env("MS_TENANT_ID"), env("MS_CLIENT_ID"), env("MS_CLIENT_SECRET")
    base, key = env("SENTINELFORGE_URL").rstrip("/"), env("SENTINELFORGE_INGEST_KEY")
    if not base.startswith("https://") and not base.startswith("http://127.0.0.1") and not base.startswith("http://localhost"):
        sys.exit("SENTINELFORGE_URL must use https")
    state: dict[str, str] = json.loads(state_file.read_text()) if state_file.exists() else {}
    default_since = (datetime.now(UTC) - timedelta(minutes=lookback_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    token = graph_token(tenant, client_id, secret)
    ok = True
    for fmt in streams:
        path, field = STREAMS[fmt]
        since = state.get(fmt, default_since)
        try:
            records = fetch(token, path, field, since)
            if records:
                totals = ship(base, key, fmt, records)
                newest = max(str(r.get(field) or "") for r in records)
                if newest:
                    state[fmt] = newest
                log(f"{fmt}: {len(records)} fetched, {totals['inserted']} new, {totals['duplicates']} duplicate, {totals['skipped']} skipped, {totals['alerts_created']} alerts")
            else:
                log(f"{fmt}: nothing new since {since}")
        except RuntimeError as exc:
            ok = False
            log(f"{fmt}: FAILED: {exc}")
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2))
    return ok


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--streams", default=",".join(STREAMS), help="comma-separated: " + ", ".join(STREAMS))
    p.add_argument("--state", default=str(Path(__file__).with_name(".graph_shipper_state.json")), help="checkpoint file")
    p.add_argument("--lookback", type=int, default=60, help="minutes to fetch on the first run")
    p.add_argument("--loop", type=int, default=0, help="seconds between passes; 0 runs once")
    args = p.parse_args()
    streams = [s.strip() for s in args.streams.split(",") if s.strip()]
    if unknown := set(streams) - set(STREAMS):
        sys.exit(f"Unknown stream(s): {', '.join(sorted(unknown))}")
    while True:
        ok = run_once(Path(args.state), streams, args.lookback)
        if not args.loop:
            sys.exit(0 if ok else 1)
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
