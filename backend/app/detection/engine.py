"""Run detection rules against stored events and persist deduplicated alerts."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.detection.base import DetectionContext, EventView, Match
from app.detection.fixtures import CASES
from app.detection.rules import ALL_RULES, MAX_LOOKBACK_MINUTES, RULES_BY_ID, Rule
from app.models import Alert, AlertEvent, DetectionRule, DetectionTestRun, Event, Indicator

# Full-capture log lines no rule reads; loading them would only slow every run down.
PASSIVE_EVENT_TYPES = ("system.log",)


def to_view(e: Event) -> EventView:
    return EventView(
        id=str(e.id),
        event_time=e.event_time,
        event_type=e.event_type,
        outcome=e.outcome,
        host=e.host,
        user_name=e.user_name,
        src_ip=e.src_ip,
        dst_ip=e.dst_ip,
        dst_port=e.dst_port,
        domain=e.domain,
        url=e.url,
        process_name=e.process_name,
        command_line=e.command_line,
        parent_process=e.parent_process,
        file_hash=e.file_hash,
        target_user=e.target_user,
        group_name=e.group_name,
        email_sender=e.email_sender,
        email_subject=e.email_subject,
        bytes_out=e.bytes_out,
        message=e.message,
        raw=e.raw or {},
    )


def sync_rule_metadata(db: Session) -> None:
    """Mirror rule metadata from code into the detection_rules table (keeps the enabled flag)."""
    for rule in ALL_RULES:
        meta = rule.metadata()
        stmt = pg_insert(DetectionRule).values(**meta, enabled=True)
        stmt = stmt.on_conflict_do_update(
            index_elements=[DetectionRule.id],
            set_={k: stmt.excluded[k] for k in meta if k != "id"} | {"updated_at": func.now()},
        )
        db.execute(stmt)


@dataclass
class RunSummary:
    events_evaluated: int
    matches: int
    alerts_created: int
    alerts_updated: int
    alert_ids: list[str]
    duration_ms: float


def _detection_context(db: Session, org_id: uuid.UUID) -> DetectionContext:
    rows = db.execute(select(Indicator.ioc_type, Indicator.value).where(Indicator.org_id == org_id, Indicator.analyst_verdict == "malicious")).all()
    return DetectionContext(
        watchlist_ips={v for t, v in rows if t in ("ipv4", "ipv6")},
        watchlist_domains={v for t, v in rows if t == "domain"},
    )


def run_detection(
    db: Session,
    org_id: uuid.UUID,
    since: datetime,
    until: datetime | None = None,
    ctx: RequestContext | None = None,
) -> RunSummary:
    """Evaluate enabled rules over events in [since, until] (plus rule lookback).

    Alerts are upserted on (org_id, dedup_key) and their event links are
    inserted idempotently, so re-running over the same window never creates
    duplicate alerts or inflates occurrence counts.
    """
    started = time.perf_counter()
    until = until or datetime.now(UTC)
    sync_rule_metadata(db)
    enabled = {r for (r,) in db.execute(select(DetectionRule.id).where(DetectionRule.enabled.is_(True))).all()}

    window_start = since - timedelta(minutes=MAX_LOOKBACK_MINUTES)
    rows = (
        db.execute(
            select(Event)
            .where(Event.org_id == org_id, Event.event_time >= window_start, Event.event_time <= until, Event.event_type.not_in(PASSIVE_EVENT_TYPES))
            .order_by(Event.event_time)
        )
        .scalars()
        .all()
    )
    views = [to_view(e) for e in rows]
    det_ctx = _detection_context(db, org_id)

    matches: list[Match] = []
    for rule in ALL_RULES:
        if rule.id in enabled:
            # Only report matches that end inside the requested window; the
            # lookback exists purely to give correlation rules their context.
            matches.extend(m for m in rule.evaluate(views, det_ctx) if m.last_seen >= since)

    created, updated, alert_ids = 0, 0, []
    for m in matches:
        alert_id, inserted = _upsert_alert(db, org_id, m)
        alert_ids.append(str(alert_id))
        if inserted:
            created += 1
            audit.record(
                db,
                ctx or audit.SYSTEM_CONTEXT,
                "alert.created",
                target_type="alert",
                target_id=alert_id,
                details={"rule_id": m.rule_id, "event_count": len(m.event_ids)},
                org_id=org_id,
            )
        else:
            updated += 1

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    if ctx is not None:
        audit.record(
            db,
            ctx,
            "detection.run",
            target_type="organization",
            target_id=org_id,
            details={
                "since": since.isoformat(),
                "until": until.isoformat(),
                "events": len(views),
                "alerts_created": created,
                "alerts_updated": updated,
                "duration_ms": duration_ms,
            },
        )
    return RunSummary(len(views), len(matches), created, updated, alert_ids, duration_ms)


def _upsert_alert(db: Session, org_id: uuid.UUID, m: Match) -> tuple[uuid.UUID, bool]:
    rule = RULES_BY_ID[m.rule_id]
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "org_id": org_id,
        "rule_id": m.rule_id,
        "title": m.title[:300],
        "description": m.description,
        "severity": m.severity or rule.severity,
        "confidence": rule.confidence,
        "status": "new",
        "dedup_key": m.dedup_key[:200],
        "occurrence_count": len(m.event_ids),
        "first_seen": m.first_seen,
        "last_seen": m.last_seen,
        "entities": {k: v for k, v in m.entities.items() if v is not None},
        "evidence_summary": m.evidence,
    }
    stmt = pg_insert(Alert).values(**values)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_alerts_org_dedup",
        set_={
            "first_seen": func.least(Alert.first_seen, stmt.excluded.first_seen),
            "last_seen": func.greatest(Alert.last_seen, stmt.excluded.last_seen),
            "evidence_summary": stmt.excluded.evidence_summary,
            "updated_at": func.now(),
        },
    ).returning(Alert.id, (Alert.id == values["id"]).label("inserted"))
    alert_id, inserted = db.execute(stmt).one()

    if m.event_ids:
        db.execute(pg_insert(AlertEvent).values([{"alert_id": alert_id, "event_id": uuid.UUID(eid)} for eid in m.event_ids]).on_conflict_do_nothing())
    count = db.execute(select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert_id)).scalar_one()
    db.execute(update(Alert).where(Alert.id == alert_id).values(occurrence_count=count))
    return alert_id, bool(inserted)


# --- evaluation against labelled fixtures ------------------------------------


def evaluate_rule(rule: Rule) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    cases_out = []
    unexpected_failures = 0
    started = time.perf_counter()
    for case in CASES.get(rule.id, []):
        fired = bool(rule.evaluate(case.events, case.context))
        malicious = case.label == "malicious"
        if malicious and fired:
            tp += 1
            outcome = "TP"
        elif malicious and not fired:
            fn += 1
            outcome = "FN"
        elif not malicious and fired:
            fp += 1
            outcome = "FP"
        else:
            tn += 1
            outcome = "TN"
        correct = outcome in ("TP", "TN")
        if not correct and not case.known_limitation:
            unexpected_failures += 1
        cases_out.append({"name": case.name, "label": case.label, "outcome": outcome, "known_limitation": case.known_limitation})
    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {
        "rule_id": rule.id,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 3) if precision is not None else None,
        "recall": round(recall, 3) if recall is not None else None,
        "latency_ms": latency_ms,
        "passed": unexpected_failures == 0 and len(cases_out) > 0,
        "cases": cases_out,
    }


def run_self_test(db: Session, triggered_by: uuid.UUID | None) -> list[dict[str, Any]]:
    sync_rule_metadata(db)
    results = []
    for rule in ALL_RULES:
        r = evaluate_rule(rule)
        db.add(
            DetectionTestRun(
                rule_id=rule.id,
                true_positives=r["true_positives"],
                false_positives=r["false_positives"],
                true_negatives=r["true_negatives"],
                false_negatives=r["false_negatives"],
                precision=r["precision"],
                recall=r["recall"],
                latency_ms=r["latency_ms"],
                passed=r["passed"],
                details={"cases": r["cases"]},
                triggered_by=triggered_by,
            )
        )
        results.append(r)
    return results
