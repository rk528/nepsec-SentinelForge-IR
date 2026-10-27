"""Detection engine primitives.

Rules operate on ``EventView`` objects, a plain, read-only projection of a
normalised event. This keeps rules independent of the ORM so the same code
runs against database rows and against in-memory labelled test fixtures.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

# Ranges treated as internal. Documentation ranges (RFC 5737, used by the
# synthetic scenarios) are deliberately *not* listed, so they behave as
# external addresses without ever pointing at a real third party.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_internal_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETWORKS)


def is_external_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return not is_internal_ip(value)


@dataclass(frozen=True)
class EventView:
    id: str
    event_time: datetime
    event_type: str
    outcome: str | None = None
    host: str | None = None
    user_name: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    domain: str | None = None
    url: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    file_hash: str | None = None
    target_user: str | None = None
    group_name: str | None = None
    email_sender: str | None = None
    email_subject: str | None = None
    bytes_out: int | None = None


@dataclass
class DetectionContext:
    """Extra knowledge a rule may use beyond the events themselves."""

    watchlist_ips: set[str] = field(default_factory=set)
    watchlist_domains: set[str] = field(default_factory=set)


@dataclass
class Match:
    rule_id: str
    dedup_key: str
    title: str
    description: str
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    entities: dict[str, Any]
    evidence: dict[str, Any]
    severity: str | None = None  # overrides the rule default when set


class Rule:
    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[str]
    confidence: ClassVar[str]
    rationale: ClassVar[str]
    required_telemetry: ClassVar[list[str]]
    false_positives: ClassVar[list[str]]
    attack_techniques: ClassVar[list[str]]
    version: ClassVar[int] = 1
    # How far before the evaluated window this rule needs to look for context.
    lookback_minutes: ClassVar[int] = 0

    def evaluate(self, events: list[EventView], ctx: DetectionContext) -> list[Match]:
        raise NotImplementedError

    @classmethod
    def metadata(cls) -> dict[str, Any]:
        return {
            "id": cls.id,
            "name": cls.name,
            "description": cls.description,
            "severity": cls.severity,
            "confidence": cls.confidence,
            "rationale": cls.rationale,
            "required_telemetry": cls.required_telemetry,
            "false_positives": cls.false_positives,
            "attack_techniques": cls.attack_techniques,
            "version": cls.version,
        }


def of_type(events: Iterable[EventView], *types: str) -> list[EventView]:
    wanted = set(types)
    return [e for e in events if e.event_type in wanted]


def lower(value: str | None) -> str:
    return (value or "").lower()
