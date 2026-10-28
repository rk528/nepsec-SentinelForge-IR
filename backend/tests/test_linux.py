"""Linux journal ingestion (Ubuntu Server and Desktop): mapping, detections end to end, shipper.

Records follow ``journalctl -o json`` output with synthetic values (RFC 5737 addresses).
"""

from __future__ import annotations

import importlib.util
import itertools
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.connectors.linux import map_linux_payload
from tests.helpers import create_source

SHIPPER_PATH = Path(__file__).resolve().parents[2] / "connectors" / "linux" / "sentinelforge_linux_shipper.py"
BOOT = "4f0c1b2d9e8a4b7c8d6e5f4a3b2c1d0e"
_seq = itertools.count(1)


def jr(minutes: float, ident: str, message: Any, host: str = "ubuntu-srv-01", **extra: Any) -> dict[str, Any]:
    when = datetime.now(UTC) - timedelta(minutes=30) + timedelta(minutes=minutes)
    n = next(_seq)
    return {
        "__CURSOR": f"s=abc;i={n:x}",
        "__REALTIME_TIMESTAMP": str(int(when.timestamp() * 1_000_000)),
        "_BOOT_ID": BOOT,
        "_HOSTNAME": host,
        "SYSLOG_IDENTIFIER": ident,
        "_PID": str(1000 + n),
        "MESSAGE": message,
        **extra,
    }


def _post(api, key: str, records: list[dict[str, Any]]):
    return api.client.post("/api/v1/ingest/linux", json={"records": records}, headers={"Authorization": f"Bearer {key}"})


def _alerts(api) -> list[dict[str, Any]]:
    return api.get("/api/v1/alerts", params={"page_size": 100}).json()["items"]


def test_ssh_brute_force_on_ubuntu_server_raises_alert(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "ubuntu-srv-01 journal")
    records = [jr(i * 0.4, "sshd", f"Failed password for deploy from 203.0.113.50 port {40000 + i} ssh2") for i in range(6)]
    records += [
        jr(3, "sshd", "Accepted password for deploy from 203.0.113.50 port 40100 ssh2"),
        # Noise that must be skipped, not counted as extra failures.
        jr(3.1, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)"),
        jr(3.2, "sshd", "Invalid user admin from 198.51.100.9 port 51000"),
        jr(3.3, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"),
    ]
    r = _post(admin, key, records)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["inserted"] == 7 and body["skipped"] == 3 and body["alerts_created"] == 1
    [alert] = [a for a in _alerts(admin) if a["rule_id"] == "SF-AUTH-001"]
    assert "deploy" in alert["title"]


def test_new_sudo_user_on_ubuntu_names_the_admin_who_ran_it(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "ubuntu-srv-01 journal")
    records = [
        jr(1, "sudo", "    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc_tmp"),
        jr(1.01, "useradd", "new group: name=svc_tmp, GID=1005"),
        jr(1.02, "useradd", "new user: name=svc_tmp, UID=1005, GID=1005, home=/home/svc_tmp, shell=/bin/bash, from=/dev/pts/0"),
        jr(2, "sudo", "    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc_tmp"),
        jr(2.01, "usermod", "add 'svc_tmp' to group 'sudo'"),
        jr(2.02, "usermod", "add 'svc_tmp' to shadow group 'sudo'"),
    ]
    body = _post(admin, key, records).json()
    assert body["inserted"] == 4 and body["skipped"] == 2, body
    [alert] = [a for a in _alerts(admin) if a["rule_id"] == "SF-IAM-001"]
    assert alert["entities"]["user"] == "alice" and alert["entities"]["target_user"] == "svc_tmp" and alert["entities"]["group"] == "sudo"


def test_logging_stopped_alerts_but_shutdown_does_not(api_for) -> None:
    admin = api_for("admin")
    key = create_source(admin, "ubuntu-srv-01 journal")
    other_boot = "aaaabbbbccccddddeeeeffff00001111"
    records = [
        jr(1, "systemd", "Stopped rsyslog.service - System Logging Service.", UNIT="rsyslog.service"),
        # A reboot stops everything; in that boot the stops are expected.
        jr(5, "systemd-logind", "System is rebooting.", host="ubuntu-desk-07", _BOOT_ID=other_boot),
        jr(5.1, "systemd", "Stopped auditd.service - Security Auditing Service.", host="ubuntu-desk-07", _BOOT_ID=other_boot, UNIT="auditd.service"),
        # Older systemd prints only the description; the UNIT field names the service.
        jr(6, "systemd", "Stopped Security Auditing Service.", host="ubuntu-srv-02", UNIT="auditd.service"),
        jr(7, "systemd", "Stopped cups.service - CUPS Scheduler.", UNIT="cups.service"),
    ]
    _post(admin, key, records)
    hosts = sorted(a["entities"]["host"] for a in _alerts(admin) if a["rule_id"] == "SF-DEF-001")
    assert hosts == ["ubuntu-srv-01", "ubuntu-srv-02"]


def test_ubuntu_desktop_sign_ins_and_sudo() -> None:
    records = [
        jr(1, "gdm-password]", "pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=maya", host="ubuntu-desk-07"),
        jr(2, "gdm-password]", "pam_unix(gdm-password:session): session opened for user maya(uid=1000) by (uid=0)", host="ubuntu-desk-07"),
        jr(3, "sudo", "pam_unix(sudo:auth): authentication failure; logname=maya uid=1000 euid=0 tty=/dev/pts/1 ruser=maya rhost=  user=maya", host="ubuntu-desk-07"),
        jr(4, "sudo", "    maya : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/maya ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", host="ubuntu-desk-07"),
        jr(5, "su", "pam_unix(su:session): session opened for user root(uid=0) by maya(uid=1000)", host="ubuntu-desk-07"),
        jr(6, "sshd-session", "Accepted publickey for maya from 2001:db8::7 port 52000 ssh2: ED25519 SHA256:abc", host="ubuntu-desk-07"),
        # Non-UTF-8 messages arrive as byte arrays.
        jr(7, "sudo", list(b"    maya : TTY=pts/1 ; PWD=/home/maya ; USER=root ; COMMAND=/usr/bin/apt update"), host="ubuntu-desk-07"),
    ]
    events, skipped = map_linux_payload({"records": records})
    assert skipped == 0
    gdm_fail, gdm_ok, sudo_fail, denied, su, ssh, apt = events
    assert (gdm_fail.event_type, gdm_fail.user_name, gdm_fail.src_ip) == ("auth.failure", "maya", None)
    assert gdm_ok.event_type == "auth.success" and gdm_ok.raw["logon"] == "interactive"
    assert sudo_fail.event_type == "auth.failure" and sudo_fail.raw["pam_service"] == "sudo"
    assert denied.event_type == "auth.failure" and denied.outcome == "denied" and denied.target_user == "root"
    assert su.user_name == "maya" and su.target_user == "root"
    assert ssh.src_ip == "2001:db8::7" and ssh.raw["method"] == "publickey"
    assert apt.event_type == "process.start" and apt.process_name == "apt" and apt.command_line == "/usr/bin/apt update" and apt.parent_process == "sudo"
    assert all(e.host == "ubuntu-desk-07" for e in events)


def test_gpasswd_and_garbage() -> None:
    records = [
        jr(1, "gpasswd", "user bob added by root to group docker"),
        jr(2, "gpasswd", "members of group lxd set by root to bob,carol"),
        jr(3, "sshd", "Failed password for x from not-an-ip port 1 ssh2"),
        {"MESSAGE": "no timestamp"},
        "not a record",
    ]
    events, skipped = map_linux_payload(records)
    groups = [(e.target_user, e.group_name) for e in events if e.event_type == "iam.group_member_added"]
    assert groups == [("bob", "docker"), ("bob", "lxd"), ("carol", "lxd")]
    # The failed login with a hostname instead of an IP is still recorded, without src_ip.
    [failure] = [e for e in events if e.event_type == "auth.failure"]
    assert failure.src_ip is None and failure.user_name == "x"
    # The record without a timestamp is skipped; a non-object is not a record at all.
    assert skipped == 1


def test_linux_ingest_requires_key_and_limits(api_for, app) -> None:
    from fastapi.testclient import TestClient

    assert TestClient(app).post("/api/v1/ingest/linux", json={"records": []}).status_code == 401
    admin = api_for("admin")
    key = create_source(admin)
    big = [jr(0, "sshd", "Failed password for a from 203.0.113.1 port 1 ssh2")] * 501
    assert _post(admin, key, big).status_code == 413


# --- shipper ---------------------------------------------------------------------


@pytest.fixture
def shipper():
    spec = importlib.util.spec_from_file_location("sentinelforge_linux_shipper", SHIPPER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipper_keeps_only_mapped_sources(shipper) -> None:
    assert shipper.wanted(jr(0, "sshd", "Failed password for a from 203.0.113.1 port 1 ssh2"))
    assert shipper.wanted(jr(0, "gdm-password]", "pam_unix(gdm-password:auth): authentication failure"))
    assert shipper.wanted(jr(0, "systemd", "Stopped auditd.service - Security Auditing Service."))
    assert not shipper.wanted(jr(0, "systemd", "Started Daily apt download activities."))
    assert not shipper.wanted(jr(0, "kernel", "audit: type=1400 apparmor=ALLOWED"))
    slim = shipper.slim(jr(0, "sshd", "x" * 5000))
    assert len(slim["MESSAGE"]) == shipper.MAX_MESSAGE and "__CURSOR" not in slim


def test_shipper_advances_cursor_only_after_delivery(shipper, tmp_path, monkeypatch) -> None:
    state = str(tmp_path / "journal.cursor")
    records = [jr(i, "systemd", "Started something.") for i in range(3)] + [jr(4, "sshd", "Accepted password for a from 203.0.113.1 port 1 ssh2")]
    monkeypatch.setattr(shipper, "journal", lambda cursor, lookback, journalctl="journalctl": iter(records))
    sent: list[list[dict[str, Any]]] = []

    def ok(url, key, batch, timeout=30.0, **kw):
        sent.append(list(batch))
        return {"inserted": len(batch), "alerts_created": 0}

    monkeypatch.setattr(shipper, "post", ok)
    totals = shipper.run("https://api.example.test", "sfk_x", state, 60)
    assert totals == {"read": 4, "sent": 1, "inserted": 1, "alerts": 0}
    assert sent[0][0]["SYSLOG_IDENTIFIER"] == "sshd" and sent[0][0]["_HOSTNAME"] == "ubuntu-srv-01"
    assert shipper.read_cursor(state) == records[-1]["__CURSOR"]

    def fail(url, key, batch, timeout=30.0, **kw):
        raise RuntimeError("HTTP 503")

    previous = shipper.read_cursor(state)
    monkeypatch.setattr(shipper, "journal", lambda cursor, lookback, journalctl="journalctl": iter([jr(9, "sshd", "Failed password for a from 203.0.113.1 port 2 ssh2")]))
    monkeypatch.setattr(shipper, "post", fail)
    with pytest.raises(RuntimeError):
        shipper.run("https://api.example.test", "sfk_x", state, 60)
    assert shipper.read_cursor(state) == previous  # retried from the same place next run


def test_shipper_payload_round_trips_through_the_mapper(shipper) -> None:
    raw = jr(0, "sshd", "Accepted password for deploy from 203.0.113.50 port 40100 ssh2")
    events, skipped = map_linux_payload({"records": [shipper.slim(raw)]})
    assert skipped == 0 and events[0].user_name == "deploy" and events[0].src_ip == "203.0.113.50"


# --- full capture (--capture all) -------------------------------------------------------


def _audit(minutes: float, audit_id: str, message: str, type_name: str) -> dict[str, Any]:
    return jr(minutes, "audit", message, _TRANSPORT="audit", _AUDIT_ID=audit_id, _AUDIT_TYPE_NAME=type_name, host="ubuntu-desk-07")


def test_full_capture_assembles_every_user_command(shipper, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(shipper, "user_name", lambda value: {"1000": "maya", "0": "root"}.get(str(value)))
    records = [
        _audit(
            1,
            "1730000000.100:51",
            'SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid=2100 pid=2200 auid=1000 uid=0 tty=pts1 comm="cat" exe="/usr/bin/cat" key="sf_exec"',
            "SYSCALL",
        ),
        # Arguments with spaces are hex-encoded by the kernel.
        _audit(1, "1730000000.100:51", 'EXECVE argc=2 a0="cat" a1=2F746D702F6D792066696C65', "EXECVE"),
        _audit(1, "1730000000.100:51", 'CWD cwd="/home/maya"', "CWD"),
        _audit(1, "1730000000.100:51", "PROCTITLE proctitle=636174002F746D702F6D792066696C65", "PROCTITLE"),
        jr(1.5, "gnome-shell", "Window manager warning: something", host="ubuntu-desk-07", _UID="1000"),
        # An audit event from another rule is an ordinary log line, not a command.
        _audit(2, "1730000000.200:52", 'SYSCALL arch=c000003e syscall=2 success=yes auid=1000 uid=1000 comm="vim" exe="/usr/bin/vim" key="watch_etc"', "SYSCALL"),
        # Our own run log is never shipped back.
        jr(2.5, "python3", "read 10 journal records", host="ubuntu-desk-07", _SYSTEMD_UNIT="sentinelforge-shipper.service"),
        # The last command has no EOE or successor; draining at the end still sends it.
        _audit(
            3,
            "1730000000.300:53",
            'SYSCALL arch=c000003e syscall=59 success=yes ppid=2100 pid=2300 auid=1000 uid=1000 tty=pts1 comm="ls" exe="/usr/bin/ls" key="sf_exec"',
            "SYSCALL",
        ),
        _audit(3, "1730000000.300:53", 'EXECVE argc=2 a0="ls" a1="-la"', "EXECVE"),
    ]
    monkeypatch.setattr(shipper, "journal", lambda cursor, lookback, journalctl="journalctl": iter(records))
    sent: list[dict[str, Any]] = []

    def ok(url, key, batch, timeout=30.0, capture="security"):
        assert capture == "all"
        sent.extend(batch)
        return {"inserted": len(batch), "alerts_created": 0}

    monkeypatch.setattr(shipper, "post", ok)
    totals = shipper.run("https://api.example.test", "sfk_x", str(tmp_path / "c"), 60, capture="all")
    assert totals["read"] == len(records) and totals["sent"] == 4
    events, skipped = map_linux_payload({"records": sent, "capture": "all"})
    assert skipped == 0
    cat, gnome, other_audit, ls = events
    assert (cat.event_type, cat.user_name, cat.target_user, cat.process_name) == ("process.start", "maya", "root", "cat")
    assert cat.command_line == "cat /tmp/my file" and cat.raw["cwd"] == "/home/maya" and cat.raw["source"] == "linux.auditd"
    assert gnome.event_type == "system.log" and gnome.user_name == "maya" and gnome.process_name == "gnome-shell"
    assert other_audit.event_type == "system.log"
    assert ls.command_line == "ls -la" and ls.target_user is None


def test_full_capture_maps_usb_and_session_end_and_keeps_the_rest() -> None:
    records = [
        jr(1, "kernel", "usb 1-1: New USB device found, idVendor=0781, idProduct=5567, bcdDevice= 1.00", host="ubuntu-desk-07"),
        jr(2, "gdm-password]", "pam_unix(gdm-password:session): session closed for user maya", host="ubuntu-desk-07"),
        jr(3, "NetworkManager", "<info>  [1730000000.1] device (ens33): state change: activated", host="ubuntu-desk-07", PRIORITY="6"),
    ]
    events, skipped = map_linux_payload({"records": records, "capture": "all"})
    usb, closed, nm = events
    assert usb.event_type == "device.connected" and usb.raw["vendor_id"] == "0781"
    assert closed.event_type == "session.ended" and closed.user_name == "maya"
    assert nm.event_type == "system.log" and nm.raw["priority"] == "6" and skipped == 0
    # Without full capture the unmapped line is skipped as before.
    assert map_linux_payload({"records": records[2:]})[1] == 1


def test_full_capture_lines_skip_detection_and_expire(api_for, db) -> None:
    from sqlalchemy import func, select, update

    from app.models import Event

    admin = api_for("admin")
    key = create_source(admin, "ubuntu-desk-07 journal")
    lines = [jr(i * 0.01, "NetworkManager", f"line {i}", host="ubuntu-desk-07") for i in range(5)]
    r = admin.client.post("/api/v1/ingest/linux", json={"records": lines, "capture": "all"}, headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200 and r.json()["inserted"] == 5 and r.json()["alerts_created"] == 0
    # Age them past the retention window; the next full-capture batch deletes them.
    db.execute(update(Event).where(Event.event_type == "system.log").values(event_time=func.now() - __import__("datetime").timedelta(days=10)))
    db.commit()
    admin.client.post(
        "/api/v1/ingest/linux", json={"records": [jr(20, "NetworkManager", "fresh", host="ubuntu-desk-07")], "capture": "all"}, headers={"Authorization": f"Bearer {key}"}
    )
    db.expire_all()
    messages = [m for (m,) in db.execute(select(Event.message).where(Event.event_type == "system.log")).all()]
    assert messages == ["fresh"]
