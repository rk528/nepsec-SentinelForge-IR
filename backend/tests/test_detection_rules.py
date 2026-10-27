"""Unit tests for detection logic (no database)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.detection.base import DetectionContext, EventView, is_external_ip
from app.detection.engine import evaluate_rule
from app.detection.fixtures import CASES, T0
from app.detection.rules import ALL_RULES, RULES_BY_ID


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_passes_labelled_fixtures(rule) -> None:
    result = evaluate_rule(rule)
    assert result["passed"], result["cases"]
    # Every rule has both malicious and benign coverage.
    labels = {c.label for c in CASES[rule.id]}
    assert labels == {"malicious", "benign"}


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_metadata_is_complete(rule) -> None:
    meta = rule.metadata()
    for key in ("id", "name", "description", "severity", "confidence", "rationale"):
        assert meta[key], key
    assert meta["required_telemetry"] and meta["false_positives"]
    assert meta["attack_techniques"] or rule.external_attack_mapping
    assert meta["severity"] in ("low", "medium", "high", "critical")


def test_rule_ids_are_unique() -> None:
    assert len(RULES_BY_ID) == len(ALL_RULES)


def test_known_limitations_are_reported_not_hidden() -> None:
    result = evaluate_rule(RULES_BY_ID["SF-AUTH-001"])
    slow = next(c for c in result["cases"] if c["name"] == "slow guessing spread over 30 minutes")
    assert slow["outcome"] == "FN" and slow["known_limitation"]
    assert result["recall"] < 1.0


def test_auth_rule_preserves_triggering_event_ids() -> None:
    case = CASES["SF-AUTH-001"][0]
    [match] = RULES_BY_ID["SF-AUTH-001"].evaluate(case.events, DetectionContext())
    assert set(match.event_ids) == {e.id for e in case.events}
    assert match.evidence["failure_count"] == 8


def test_auth_rule_threshold_boundary() -> None:
    rule = RULES_BY_ID["SF-AUTH-001"]

    def seq(n: int) -> list[EventView]:
        evs = [EventView(id=f"f{i}", event_time=T0 + timedelta(seconds=i), event_type="auth.failure", user_name="u", src_ip="203.0.113.1") for i in range(n)]
        return evs + [EventView(id="s", event_time=T0 + timedelta(minutes=1), event_type="auth.success", user_name="u", src_ip="203.0.113.1")]

    assert not rule.evaluate(seq(4), DetectionContext())
    assert rule.evaluate(seq(5), DetectionContext())


def test_process_rule_reports_specific_technique() -> None:
    case = next(c for c in CASES["SF-PROC-001"] if c.name == "shadow copies deleted")
    [match] = RULES_BY_ID["SF-PROC-001"].evaluate(case.events, DetectionContext())
    assert match.severity == "critical"
    assert match.evidence["techniques"] == ["T1490"]


def test_process_rule_treats_command_line_as_data() -> None:
    hostile = EventView(
        id="x",
        event_time=T0,
        event_type="process.start",
        host="h",
        command_line="<script>alert(1)</script> $(rm -rf /) ; DROP TABLE events; --",
    )
    assert RULES_BY_ID["SF-PROC-001"].evaluate([hostile], DetectionContext()) == []


def test_network_rule_watchlist_raises_severity() -> None:
    case = next(c for c in CASES["SF-NET-001"] if c.name == "watchlisted destination")
    [match] = RULES_BY_ID["SF-NET-001"].evaluate(case.events, case.context)
    assert match.severity == "high"
    assert "destination on watchlist" in match.evidence["reasons"]


@pytest.mark.parametrize(
    ("ip", "external"),
    [
        ("10.1.2.3", False),
        ("192.168.0.1", False),
        ("172.20.0.1", False),
        ("127.0.0.1", False),
        ("203.0.113.5", True),
        ("8.8.8.8", True),
        ("not-an-ip", False),
        (None, False),
        ("fe80::1", False),
        ("2001:db8::1", True),
    ],
)
def test_is_external_ip(ip, external) -> None:
    assert is_external_ip(ip) is external
