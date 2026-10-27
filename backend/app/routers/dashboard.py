"""Executive overview. Every number here is computed from stored records."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import Principal, Viewer
from app.models import Alert, Asset, AuditLog, DataSource, DetectionRule, Event, Incident, Organization
from app.services.incidents import reference

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

OPEN_STATUSES = ("new", "open", "investigating", "contained")


def _day_series(rows: list[tuple[Any, ...]], start: datetime, days: int, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    """Fill a per-day series with zeros so charts have a point for every day."""
    buckets: dict[str, dict[str, int]] = {}
    for day, key, count in rows:
        buckets.setdefault(day.date().isoformat(), {})[key] = int(count)
    out = []
    for i in range(days + 1):
        d = (start + timedelta(days=i)).date().isoformat()
        out.append({"date": d, **{k: buckets.get(d, {}).get(k, 0) for k in keys}})
    return out


def _avg_minutes(db: Session, org_id: Any, start: datetime, column: Any) -> dict[str, Any]:
    row = db.execute(
        select(func.avg(func.extract("epoch", column - Incident.created_at)) / 60, func.count()).where(Incident.org_id == org_id, Incident.created_at >= start, column.is_not(None))
    ).one()
    avg, n = row
    return {"minutes": round(float(avg), 1) if avg is not None else None, "sample_size": int(n)}


@router.get("/summary")
def summary(days: int = Query(14, ge=1, le=90), principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    org_id = principal.org_id
    now = datetime.now(UTC)
    start = (now - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    sev_keys = ("critical", "high", "medium", "low", "informational")

    open_by_sev = dict(db.execute(select(Incident.severity, func.count()).where(Incident.org_id == org_id, Incident.status.in_(OPEN_STATUSES)).group_by(Incident.severity)).all())
    status_dist = dict(
        db.execute(
            select(Incident.status, func.count()).where(Incident.org_id == org_id, (Incident.status.in_(OPEN_STATUSES)) | (Incident.updated_at >= start)).group_by(Incident.status)
        ).all()
    )

    day = func.date_trunc("day", Incident.created_at)
    incident_rows = db.execute(select(day, Incident.severity, func.count()).where(Incident.org_id == org_id, Incident.created_at >= start).group_by(day, Incident.severity)).all()
    aday = func.date_trunc("day", Alert.first_seen)
    alert_rows = db.execute(select(aday, Alert.severity, func.count()).where(Alert.org_id == org_id, Alert.first_seen >= start).group_by(aday, Alert.severity)).all()

    by_rule = db.execute(
        select(Alert.rule_id, DetectionRule.name, func.count())
        .join(DetectionRule, DetectionRule.id == Alert.rule_id)
        .where(Alert.org_id == org_id, Alert.first_seen >= start)
        .group_by(Alert.rule_id, DetectionRule.name)
        .order_by(func.count().desc())
    ).all()
    alert_status = dict(db.execute(select(Alert.status, func.count()).where(Alert.org_id == org_id, Alert.first_seen >= start).group_by(Alert.status)).all())

    sev_order = case({"critical": 0, "high": 1, "medium": 2, "low": 3}, value=Incident.severity, else_=4)
    priority = (
        db.execute(
            select(Incident)
            .where(Incident.org_id == org_id, Incident.status.in_(OPEN_STATUSES), Incident.severity.in_(("critical", "high")))
            .order_by(sev_order, Incident.created_at.desc())
            .limit(6)
        )
        .scalars()
        .all()
    )

    events_by_source = dict(db.execute(select(Event.data_source_id, func.count()).where(Event.org_id == org_id, Event.event_time >= start).group_by(Event.data_source_id)).all())
    sources = db.execute(select(DataSource).where(DataSource.org_id == org_id).order_by(DataSource.name)).scalars().all()
    stale_after = now - timedelta(hours=24)

    asset_total, assets_reporting = db.execute(select(func.count(), func.count().filter(Asset.last_telemetry_at >= stale_after)).where(Asset.org_id == org_id)).one()

    recent = (
        db.execute(
            select(AuditLog).where(AuditLog.org_id == org_id, AuditLog.actor_user_id.is_not(None), ~AuditLog.action.like("auth.%")).order_by(AuditLog.created_at.desc()).limit(8)
        )
        .scalars()
        .all()
    )
    org = db.get(Organization, org_id)

    return {
        "range": {"days": days, "start": start.isoformat(), "end": now.isoformat()},
        "synthetic": bool(org and org.is_demo),
        "open_incidents": {"total": sum(open_by_sev.values()), "by_severity": {k: open_by_sev.get(k, 0) for k in sev_keys}},
        "incident_status": {k: status_dist.get(k, 0) for k in ("new", "open", "investigating", "contained", "resolved", "closed")},
        "incident_trend": _day_series(incident_rows, start, days, sev_keys),
        "alert_trend": _day_series(alert_rows, start, days, sev_keys),
        "detections": {
            "total": sum(c for _, _, c in by_rule),
            "by_rule": [{"rule_id": r, "name": n, "count": c} for r, n, c in by_rule],
            "by_status": {k: alert_status.get(k, 0) for k in ("new", "acknowledged", "escalated", "closed")},
        },
        "mtta": _avg_minutes(db, org_id, start, Incident.acknowledged_at),
        "mttr": _avg_minutes(db, org_id, start, Incident.resolved_at),
        "priority_incidents": [
            {"id": str(i.id), "reference": reference(i.number), "title": i.title, "severity": i.severity, "status": i.status, "created_at": i.created_at.isoformat()}
            for i in priority
        ],
        "telemetry": {
            "sources": [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "source_type": s.source_type,
                    "events_in_range": int(events_by_source.get(s.id, 0)),
                    "last_event_at": s.last_event_at.isoformat() if s.last_event_at else None,
                    "healthy": bool(s.is_enabled and s.last_event_at and s.last_event_at >= stale_after),
                    "is_synthetic": s.is_synthetic,
                }
                for s in sources
            ],
            "assets_total": int(asset_total),
            "assets_reporting_24h": int(assets_reporting),
        },
        "recent_activity": [
            {"id": str(a.id), "actor": a.actor_label, "action": a.action, "target_type": a.target_type, "target_id": a.target_id, "at": a.created_at.isoformat()} for a in recent
        ],
    }
