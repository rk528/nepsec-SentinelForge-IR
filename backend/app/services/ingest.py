"""Event ingestion: normalise, de-duplicate, store, and update source health."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import AlertEvent, Asset, DataSource, Event, IncidentEvent
from app.schemas import EventIn


def fingerprint(org_id: uuid.UUID, data_source_id: uuid.UUID, ev: EventIn) -> str:
    """Stable hash so that re-sending the same event is idempotent."""
    payload = ev.model_dump(mode="json")
    canonical = json.dumps({"org": str(org_id), "src": str(data_source_id), "event": payload}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class IngestResult:
    received: int
    inserted: int
    inserted_ids: list[uuid.UUID]
    earliest: datetime | None


def ingest_events(
    db: Session,
    org_id: uuid.UUID,
    source: DataSource,
    events: list[EventIn],
    *,
    synthetic: bool = False,
    scenario_id: str | None = None,
) -> IngestResult:
    if not events:
        return IngestResult(0, 0, [], None)

    hosts = {e.host for e in events if e.host}
    asset_ids = _ensure_assets(db, org_id, hosts, events)

    rows: list[dict[str, Any]] = []
    for ev in events:
        data = ev.model_dump(exclude={"raw"})
        rows.append(
            {
                "id": uuid.uuid4(),
                "org_id": org_id,
                "data_source_id": source.id,
                "asset_id": asset_ids.get(ev.host) if ev.host else None,
                **data,
                "raw": ev.raw,
                "is_synthetic": synthetic,
                "scenario_id": scenario_id,
                "fingerprint": fingerprint(org_id, source.id, ev),
            }
        )

    stmt = pg_insert(Event).values(rows).on_conflict_do_nothing(constraint="uq_events_org_fingerprint").returning(Event.id)
    inserted_ids = list(db.execute(stmt).scalars().all())

    latest = max(e.event_time for e in events)
    db.execute(
        update(DataSource)
        .where(DataSource.id == source.id)
        .values(
            event_count=DataSource.event_count + len(inserted_ids),
            last_event_at=func.greatest(func.coalesce(DataSource.last_event_at, latest), latest),
        )
    )
    return IngestResult(len(events), len(inserted_ids), inserted_ids, min(e.event_time for e in events))


def purge_expired_logs(db: Session, org_id: uuid.UUID, days: int, limit: int = 5000) -> int:
    """Delete one bounded slice of expired ``system.log`` lines; called on every ingest so no cron is needed."""
    cutoff = datetime.now(UTC) - timedelta(days=max(days, 1))
    expired = (
        select(Event.id)
        .where(
            Event.org_id == org_id,
            Event.event_type == "system.log",
            Event.event_time < cutoff,
            ~exists().where(IncidentEvent.event_id == Event.id),
            ~exists().where(AlertEvent.event_id == Event.id),
        )
        .limit(limit)
    )
    return db.execute(delete(Event).where(Event.id.in_(expired.scalar_subquery()))).rowcount or 0


def _ensure_assets(db: Session, org_id: uuid.UUID, hosts: set[str], events: list[EventIn]) -> dict[str, uuid.UUID]:
    if not hosts:
        return {}
    latest_by_host: dict[str, datetime] = {}
    for e in events:
        if e.host:
            latest_by_host[e.host] = max(latest_by_host.get(e.host, e.event_time), e.event_time)

    stmt = pg_insert(Asset).values([{"id": uuid.uuid4(), "org_id": org_id, "hostname": h, "ip_addresses": [], "last_telemetry_at": latest_by_host[h]} for h in sorted(hosts)])
    stmt = stmt.on_conflict_do_update(
        constraint="uq_assets_org_hostname",
        set_={"last_telemetry_at": func.greatest(Asset.last_telemetry_at, stmt.excluded.last_telemetry_at)},
    )
    db.execute(stmt)
    rows = db.execute(select(Asset.hostname, Asset.id).where(Asset.org_id == org_id, Asset.hostname.in_(hosts))).all()
    return {h: i for h, i in rows}


def utcnow() -> datetime:
    return datetime.now(UTC)
