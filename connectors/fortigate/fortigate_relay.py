#!/usr/bin/env python3
"""Relay FortiGate syslog to SentinelForge IR.

FortiGate can only send logs over syslog, and SentinelForge runs as a web API, so
this small relay runs inside your network: FortiGate -> syslog (UDP/TCP 5514) ->
relay -> HTTPS POST /api/v1/ingest/fortigate in batches.

Standard library only (Python 3.10+). Configuration:

    SENTINELFORGE_URL         e.g. https://sentinelforge-api.kuinkel.com
    SENTINELFORGE_INGEST_KEY  sfk_... from Settings -> Data sources (type "fortigate")

    python fortigate_relay.py --allow 192.168.1.99           # FortiGate's source IP
    python fortigate_relay.py --allow 10.0.0.1 --traffic all  # forward every accepted session

Only packets from --allow addresses are accepted, so nobody else on the network can
inject fake firewall logs. Forward-traffic logs are high volume; by default only
"interesting" sessions are forwarded (see --traffic) to stay within the free database tier.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import re
import socket
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime

COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 389, 443, 465, 587, 636, 853, 993, 995, 3389, 5223, 8080, 8443}
LARGE_TRANSFER = 10 * 1024 * 1024
_FIELD = re.compile(r'\b(type|subtype|action|dstport|sentbyte|dstip)=("[^"]*"|\S+)')
# Same internal ranges as SentinelForge's detection engine (backend/app/detection/base.py).
INTERNAL = [
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")
]

state = {"received": 0, "dropped_filter": 0, "dropped_overflow": 0, "rejected_source": 0, "sent": 0, "alerts": 0}


def log(msg: str) -> None:
    print(f"{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}", flush=True)


def wanted(line: str, traffic: str) -> bool:
    """Drop routine forward-traffic noise; keep every event and UTM (security) log."""
    # FortiOS quotes most values (type="traffic"), so read the fields rather than substring-match.
    f = {k: v.strip('"') for k, v in _FIELD.findall(line)}
    if "type" not in f and "{" in line:  # JSON format
        try:
            obj = json.loads(line[line.find("{") :])
            f = {k: str(obj.get(k, "")) for k in ("type", "action", "dstport", "sentbyte", "dstip")}
        except ValueError:
            return True
    if f.get("type") != "traffic":
        return True
    if traffic == "all":
        return True
    if traffic == "none":
        return False
    if f.get("action") not in ("accept", "close", "timeout", "server-rst", "client-rst"):
        return False
    try:
        dst = ipaddress.ip_address(f.get("dstip", ""))
    except ValueError:
        return False
    if dst.is_multicast or any(dst in net for net in INTERNAL):
        return False
    port = int(f["dstport"]) if f.get("dstport", "").isdigit() else 0
    sent = int(f["sentbyte"]) if f.get("sentbyte", "").isdigit() else 0
    return port not in COMMON_PORTS or sent >= LARGE_TRANSFER


class Relay:
    def __init__(self, url: str, key: str, allow: set[str], traffic: str, batch: int, interval: float, buffer: int):
        self.endpoint = url.rstrip("/") + "/api/v1/ingest/fortigate"
        self.key, self.allow, self.traffic = key, allow, traffic
        self.batch, self.interval = batch, interval
        self.q: queue.Queue[str] = queue.Queue(maxsize=buffer)

    def accept(self, line: str, peer: str) -> None:
        if peer not in self.allow:
            state["rejected_source"] += 1
            return
        line = line.strip()
        if not line:
            return
        state["received"] += 1
        if not wanted(line, self.traffic):
            state["dropped_filter"] += 1
            return
        try:
            self.q.put_nowait(line[:16000])
        except queue.Full:
            state["dropped_overflow"] += 1

    def post(self, lines: list[str]) -> None:
        body = json.dumps({"logs": lines}).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 - https enforced in main()
            self.endpoint, data=body, method="POST",
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json", "User-Agent": "SentinelForge-FortiGateRelay/1.0"},
        )  # fmt: skip
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - https enforced in main()
                    result = json.loads(resp.read() or b"{}")
                    state["sent"] += int(result.get("inserted", 0))
                    state["alerts"] += int(result.get("alerts_created", 0))
                    return
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 413, 422):
                    log(f"SentinelForge rejected a batch (HTTP {exc.code}): {exc.read()[:200].decode('utf-8', 'replace')}")
                    return
                wait = int(exc.headers.get("Retry-After") or 2 ** (attempt + 1))
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                wait = 2 ** (attempt + 1)
                log(f"Cannot reach SentinelForge ({exc}); retrying in {wait}s")
            time.sleep(min(wait, 60))
        log(f"Gave up on a batch of {len(lines)} lines after retries")

    def sender(self) -> None:
        last_report = time.monotonic()
        while True:
            lines: list[str] = []
            deadline = time.monotonic() + self.interval
            while len(lines) < self.batch:
                try:
                    lines.append(self.q.get(timeout=max(0.05, deadline - time.monotonic())))
                except queue.Empty:
                    break
            if lines:
                self.post(lines)
            if time.monotonic() - last_report > 300:
                last_report = time.monotonic()
                log("stats " + ", ".join(f"{k}={v}" for k, v in state.items()))


def make_udp(relay: Relay):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request[0]
            for line in data.decode("utf-8", "replace").splitlines():
                relay.accept(line, self.client_address[0])

    return Handler


def make_tcp(relay: Relay):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            peer = self.client_address[0]
            if peer not in relay.allow:
                state["rejected_source"] += 1
                return
            buf = b""
            while chunk := self.request.recv(65536):
                buf += chunk
                while buf:
                    # RFC 6587 octet counting ("123 <msg>") as used by FortiGate "reliable" mode, else newline framing.
                    m = re.match(rb"(\d{1,6}) ", buf)
                    if m:
                        end = m.end() + int(m.group(1))
                        if len(buf) < end:
                            break
                        relay.accept(buf[m.end() : end].decode("utf-8", "replace"), peer)
                        buf = buf[end:]
                    elif b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        relay.accept(line.decode("utf-8", "replace"), peer)
                    else:
                        break
                if len(buf) > 1_000_000:
                    buf = b""

    return Handler


class ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--allow", required=True, help="comma-separated source IPs of your FortiGate(s)")
    p.add_argument("--bind", default="0.0.0.0")  # noqa: S104 - must accept the firewall's packets; --allow restricts senders
    p.add_argument("--port", type=int, default=5514, help="UDP and TCP port to listen on (default 5514)")
    p.add_argument("--traffic", choices=["interesting", "all", "none"], default="interesting",
                   help="forward-traffic logs: interesting = accepted sessions to public addresses on non-standard ports or >10 MiB sent")  # fmt: skip
    p.add_argument("--batch", type=int, default=200)
    p.add_argument("--interval", type=float, default=5.0, help="seconds between batches")
    p.add_argument("--buffer", type=int, default=50000, help="lines held in memory while SentinelForge is unreachable")
    args = p.parse_args()

    url = os.environ.get("SENTINELFORGE_URL", "").strip()
    key = os.environ.get("SENTINELFORGE_INGEST_KEY", "").strip()
    if not url.startswith("https://") and not url.startswith(("http://127.0.0.1", "http://localhost")):
        sys.exit("Set SENTINELFORGE_URL to the https:// API address")
    if not key.startswith("sfk_"):
        sys.exit("Set SENTINELFORGE_INGEST_KEY to the data source's ingest key (sfk_...)")
    allow = {a.strip() for a in args.allow.split(",") if a.strip()}
    for a in allow:
        ipaddress.ip_address(a)

    relay = Relay(url, key, allow, args.traffic, min(args.batch, 500), args.interval, args.buffer)
    threading.Thread(target=relay.sender, daemon=True).start()
    udp = ThreadingUDP((args.bind, args.port), make_udp(relay))
    tcp = ThreadingTCP((args.bind, args.port), make_tcp(relay))
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    log(f"Listening for FortiGate syslog on {args.bind}:{args.port} (UDP and TCP) from {', '.join(sorted(allow))}; forwarding to {relay.endpoint}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log("stopping; stats " + ", ".join(f"{k}={v}" for k, v in state.items()))
        udp.shutdown()
        tcp.shutdown()
        socket.setdefaulttimeout(1)


if __name__ == "__main__":
    main()
