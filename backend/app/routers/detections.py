from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.db import get_db
from app.deps import Admin, Analyst, Principal, Viewer, get_ctx, require_non_demo
from app.detection.attack import KNOWN_GAPS, TACTIC_ORDER, TECHNIQUES
from app.detection.engine import run_detection, run_self_test, sync_rule_metadata
from app.detection.fixtures import CASES
from app.detection.rules import ALL_RULES
from app.models import Alert, DetectionRule, DetectionTestRun
from app.schemas import DetectionRunIn

router = APIRouter(tags=["detections"])


def _latest_tests(db: Session) -> dict[str, DetectionTestRun]:
    sub = select(DetectionTestRun.rule_id, func.max(DetectionTestRun.run_at).label("m")).group_by(DetectionTestRun.rule_id).subquery()
    rows = db.execute(select(DetectionTestRun).join(sub, (sub.c.rule_id == DetectionTestRun.rule_id) & (sub.c.m == DetectionTestRun.run_at))).scalars()
    return {r.rule_id: r for r in rows}


def _test_dict(t: DetectionTestRun | None) -> dict[str, Any] | None:
    if t is None:
        return None
    return {
        "run_at": t.run_at.isoformat(),
        "passed": t.passed,
        "precision": t.precision,
        "recall": t.recall,
        "true_positives": t.true_positives,
        "false_positives": t.false_positives,
        "true_negatives": t.true_negatives,
        "false_negatives": t.false_negatives,
        "latency_ms": t.latency_ms,
        "cases": t.details.get("cases", []),
    }


@router.get("/detections")
def list_rules(principal: Principal = Viewer, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    sync_rule_metadata(db)
    db.commit()
    enabled = dict(db.execute(select(DetectionRule.id, DetectionRule.enabled)).all())
    counts = dict(db.execute(select(Alert.rule_id, func.count()).where(Alert.org_id == principal.org_id).group_by(Alert.rule_id)).all())
    last = dict(db.execute(select(Alert.rule_id, func.max(Alert.last_seen)).where(Alert.org_id == principal.org_id).group_by(Alert.rule_id)).all())
    tests = _latest_tests(db)
    return [
        {
            **r.metadata(),
            "enabled": enabled.get(r.id, True),
            "alert_count": counts.get(r.id, 0),
            "last_alert_at": last[r.id].isoformat() if last.get(r.id) else None,
            "fixture_count": len(CASES.get(r.id, [])),
            "latest_test": _test_dict(tests.get(r.id)),
            "techniques": [{"id": t, **TECHNIQUES.get(t, {"name": "Unknown", "tactic": None})} for t in r.attack_techniques],
        }
        for r in ALL_RULES
    ]


@router.post("/detections/run")
def run(body: DetectionRunIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=body.hours)
    s = run_detection(db, principal.org_id, since=since, ctx=ctx)
    db.commit()
    return {"events_evaluated": s.events_evaluated, "matches": s.matches, "alerts_created": s.alerts_created, "alerts_updated": s.alerts_updated, "duration_ms": s.duration_ms}


@router.post("/detections/self-test")
def self_test(principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    results = run_self_test(db, principal.user_id)
    audit.record(db, ctx, "detection.self_test", details={r["rule_id"]: r["passed"] for r in results})
    db.commit()
    return results


class RuleToggleIn(BaseModel):
    enabled: bool


@router.patch("/detections/{rule_id}")
def toggle_rule(
    rule_id: str,
    body: RuleToggleIn,
    principal: Principal = Admin,
    _: Principal = Depends(require_non_demo),
    ctx: RequestContext = Depends(get_ctx),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    # Rules are platform-wide in this release, so only non-demo admins may toggle them.
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = body.enabled
    audit.record(db, ctx, "detection.rule_toggled", target_type="detection_rule", target_id=rule_id, details={"enabled": body.enabled})
    db.commit()
    return {"id": rule_id, "enabled": rule.enabled}


@router.get("/attack/coverage")
def attack_coverage(principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    tests = _latest_tests(db)
    enabled = dict(db.execute(select(DetectionRule.id, DetectionRule.enabled)).all())
    alerts = db.execute(select(Alert.rule_id, Alert.evidence_summary, Alert.id, Alert.last_seen).where(Alert.org_id == principal.org_id)).all()

    tech_rules: dict[str, list[str]] = defaultdict(list)
    for r in ALL_RULES:
        for t in r.attack_techniques:
            tech_rules[t].append(r.id)

    # Observed: alerts whose rule maps to the technique. For pattern-based rules
    # that report the specific technique matched, only count that technique.
    observed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule_id, evidence, alert_id, last_seen in alerts:
        specific = evidence.get("techniques") if isinstance(evidence, dict) else None
        rule = next((r for r in ALL_RULES if r.id == rule_id), None)
        for t in specific or (rule.attack_techniques if rule else []):
            observed[t].append({"alert_id": str(alert_id), "last_seen": last_seen})

    rows = []
    for tid, meta in TECHNIQUES.items():
        rule_ids = tech_rules.get(tid, [])
        latest = [tests.get(r) for r in rule_ids if tests.get(r)]
        obs = observed.get(tid, [])
        last_obs = max((o["last_seen"] for o in obs), default=None)
        if not rule_ids:
            coverage = "gap"
        elif not any(enabled.get(r, True) for r in rule_ids):
            coverage = "disabled"
        elif latest and all(t.passed for t in latest):
            coverage = "tested"
        else:
            coverage = "untested"
        rows.append(
            {
                "technique": tid,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "rules": rule_ids,
                "coverage": coverage,
                "gap_reason": KNOWN_GAPS.get(tid),
                "alert_count": len(obs),
                "last_observed": last_obs.isoformat() if last_obs else None,
                "sample_alert_ids": [o["alert_id"] for o in obs[:5]],
                "last_tested": max((t.run_at for t in latest), default=None),
                "test_passed": all(t.passed for t in latest) if latest else None,
            }
        )
    rows.sort(key=lambda r: (TACTIC_ORDER.index(r["tactic"]) if r["tactic"] in TACTIC_ORDER else 99, r["technique"]))
    for r in rows:
        if r["last_tested"]:
            r["last_tested"] = r["last_tested"].isoformat()
    return {
        "tactics": TACTIC_ORDER,
        "techniques": rows,
        "disclaimer": (
            "Mappings show which techniques a rule is designed to surface. They are not proof of reliable detection in every "
            "environment, and this list is a small curated subset of ATT&CK, not the full matrix."
        ),
    }
