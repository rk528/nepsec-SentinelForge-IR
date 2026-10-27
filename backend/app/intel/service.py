"""IOC investigation: provider enrichment with caching, plus local sightings."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import audit
from app.audit import RequestContext
from app.config import get_settings
from app.intel.normalize import url_host
from app.intel.providers import PROVIDERS, ProviderResult
from app.models import Event, Incident, IncidentEvent, IncidentIndicator, Indicator, IndicatorEnrichment, IndicatorLookup

# Successful answers are cached for INTEL_CACHE_HOURS; failures only briefly,
# so a transient outage or rate limit does not stick.
_ERROR_TTL = timedelta(minutes=5)


def upsert_indicator(db: Session, org_id: uuid.UUID, ioc_type: str, value: str) -> Indicator:
    stmt = (
        pg_insert(Indicator)
        .values(id=uuid.uuid4(), org_id=org_id, ioc_type=ioc_type, value=value, analyst_verdict="unknown", lookup_count=0)
        .on_conflict_do_nothing(constraint="uq_indicators_org_type_value")
    )
    db.execute(stmt)
    return db.execute(select(Indicator).where(Indicator.org_id == org_id, Indicator.ioc_type == ioc_type, Indicator.value == value)).scalar_one()


def _latest_cached(db: Session, indicator_id: uuid.UUID, provider: str) -> IndicatorEnrichment | None:
    now = datetime.now(UTC)
    return db.execute(
        select(IndicatorEnrichment)
        .where(
            IndicatorEnrichment.indicator_id == indicator_id,
            IndicatorEnrichment.provider == provider,
            IndicatorEnrichment.expires_at > now,
        )
        .order_by(IndicatorEnrichment.fetched_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def enrich(db: Session, indicator: Indicator, *, force_refresh: bool) -> tuple[list[dict[str, Any]], bool]:
    """Return one result per provider. Unconfigured/unsupported providers are reported, not stored."""
    settings = get_settings()
    results: list[dict[str, Any]] = []
    all_cached = True
    for provider in PROVIDERS:
        base = {"provider": provider.name, "provider_label": provider.label, "terms_url": provider.terms_url}
        if indicator.ioc_type not in provider.supported:
            results.append({**base, "status": "unsupported", "reported_verdict": "unknown", "cached": False})
            continue
        if not provider.configured():
            results.append({**base, "status": "unconfigured", "reported_verdict": "unknown", "cached": False})
            continue
        cached = None if force_refresh else _latest_cached(db, indicator.id, provider.name)
        if cached is not None:
            results.append({**base, **_enrichment_dict(cached), "cached": True})
            continue
        all_cached = False
        result: ProviderResult = provider.lookup(indicator.ioc_type, indicator.value)
        ttl = timedelta(hours=settings.intel_cache_hours) if result.status in ("ok", "not_found") else _ERROR_TTL
        row = IndicatorEnrichment(
            indicator_id=indicator.id,
            provider=provider.name,
            status=result.status,
            reported_verdict=result.reported_verdict,
            score=result.score,
            confidence=result.confidence,
            summary=result.summary,
            error=result.error,
            fetched_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + ttl,
        )
        db.add(row)
        db.flush()
        results.append({**base, **_enrichment_dict(row), "cached": False})
    return results, all_cached


def _enrichment_dict(e: IndicatorEnrichment) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "status": e.status,
        "reported_verdict": e.reported_verdict,
        "score": e.score,
        "confidence": e.confidence,
        "summary": e.summary,
        "error": e.error,
        "fetched_at": e.fetched_at.isoformat(),
        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
    }


def _event_filter(ioc_type: str, value: str):
    if ioc_type in ("ipv4", "ipv6"):
        return or_(Event.src_ip == value, Event.dst_ip == value)
    if ioc_type == "domain":
        return Event.domain == value
    if ioc_type == "url":
        host = url_host(value)
        return or_(Event.url == value, Event.domain == host) if host else Event.url == value
    return Event.file_hash == value


def local_sightings(db: Session, org_id: uuid.UUID, ioc_type: str, value: str) -> dict[str, Any]:
    """Evidence observed in this organisation's own telemetry."""
    flt = _event_filter(ioc_type, value)
    stats = db.execute(select(func.count(), func.min(Event.event_time), func.max(Event.event_time)).where(Event.org_id == org_id, flt)).one()
    hosts = db.execute(
        select(Event.host, func.count()).where(Event.org_id == org_id, flt, Event.host.is_not(None)).group_by(Event.host).order_by(func.count().desc()).limit(10)
    ).all()
    sample = db.execute(select(Event.id, Event.event_time, Event.event_type, Event.host).where(Event.org_id == org_id, flt).order_by(Event.event_time.desc()).limit(10)).all()
    incidents = db.execute(
        select(Incident.id, Incident.number, Incident.title, Incident.status, Incident.severity)
        .join(IncidentEvent, IncidentEvent.incident_id == Incident.id)
        .join(Event, Event.id == IncidentEvent.event_id)
        .where(Incident.org_id == org_id, flt)
        .distinct()
        .limit(20)
    ).all()
    return {
        "event_count": stats[0],
        "first_seen": stats[1].isoformat() if stats[1] else None,
        "last_seen": stats[2].isoformat() if stats[2] else None,
        "hosts": [{"host": h, "count": c} for h, c in hosts],
        "sample_events": [{"id": str(i), "event_time": t.isoformat(), "event_type": et, "host": h} for i, t, et, h in sample],
        "incidents_with_matching_evidence": [{"id": str(i), "number": n, "title": t, "status": s, "severity": sev} for i, n, t, s, sev in incidents],
    }


def linked_incidents(db: Session, org_id: uuid.UUID, indicator_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = db.execute(
        select(Incident.id, Incident.number, Incident.title, Incident.status, Incident.severity)
        .join(IncidentIndicator, IncidentIndicator.incident_id == Incident.id)
        .where(IncidentIndicator.indicator_id == indicator_id, Incident.org_id == org_id)
    ).all()
    return [{"id": str(i), "number": n, "title": t, "status": s, "severity": sev} for i, n, t, s, sev in rows]


def investigate(
    db: Session,
    ctx: RequestContext,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    ioc_type: str,
    value: str,
    *,
    incident: Incident | None,
    force_refresh: bool,
) -> dict[str, Any]:
    indicator = upsert_indicator(db, org_id, ioc_type, value)
    enrichments, used_cache = enrich(db, indicator, force_refresh=force_refresh)
    indicator.lookup_count += 1
    indicator.last_looked_up = datetime.now(UTC)
    db.add(IndicatorLookup(org_id=org_id, indicator_id=indicator.id, incident_id=incident.id if incident else None, requested_by=user_id, used_cache=used_cache))
    if incident is not None:
        db.execute(pg_insert(IncidentIndicator).values(incident_id=incident.id, indicator_id=indicator.id).on_conflict_do_nothing())
    audit.record(
        db,
        ctx,
        "ioc.lookup",
        target_type="indicator",
        target_id=indicator.id,
        details={
            "ioc_type": ioc_type,
            "value": value,
            "incident_id": str(incident.id) if incident else None,
            "providers": {e["provider"]: e["status"] for e in enrichments},
        },
    )
    return {
        "indicator": indicator,
        "enrichments": enrichments,
        "local": local_sightings(db, org_id, ioc_type, value),
        "linked_incidents": linked_incidents(db, org_id, indicator.id),
    }
