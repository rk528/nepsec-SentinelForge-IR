from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit, ratelimit
from app.audit import RequestContext
from app.config import get_settings
from app.db import get_db
from app.deps import Analyst, Principal, Viewer, get_ctx
from app.intel import service as intel
from app.intel.normalize import IocError, normalise
from app.intel.providers import PROVIDERS
from app.models import Indicator, IndicatorEnrichment, IndicatorLookup, User
from app.schemas import EnrichmentOut, IndicatorOut, IocLookupIn, IocVerdictIn, Page
from app.services import incidents as inc_svc

router = APIRouter(prefix="/iocs", tags=["threat-intel"])


@router.get("/providers")
def providers(principal: Principal = Viewer) -> list[dict[str, Any]]:
    """Which providers are configured. Never returns key material."""
    return [{"name": p.name, "label": p.label, "configured": p.configured(), "supported_types": list(p.supported), "terms_url": p.terms_url} for p in PROVIDERS]


@router.post("/normalise")
def normalise_only(body: IocLookupIn, principal: Principal = Viewer) -> dict[str, str]:
    try:
        ioc_type, value = normalise(body.value)
    except IocError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return {"type": ioc_type, "value": value}


@router.post("/lookup")
def lookup(body: IocLookupIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        ioc_type, value = normalise(body.value)
    except IocError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    s = get_settings()
    ratelimit.hit(db, f"intel:{principal.org_id}", s.intel_rate_limit, s.intel_rate_window_seconds)
    incident = inc_svc.get_incident(db, principal, body.incident_id) if body.incident_id else None
    result = intel.investigate(db, ctx, principal.org_id, principal.user_id, ioc_type, value, incident=incident, force_refresh=body.force_refresh)
    db.commit()
    return {**result, "indicator": IndicatorOut.model_validate(result["indicator"])}


@router.get("", response_model=Page[IndicatorOut])
def list_indicators(
    principal: Principal = Viewer,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=200),
    verdict: str | None = Query(None, pattern="^(unknown|benign|suspicious|malicious)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> Page[IndicatorOut]:
    stmt = select(Indicator).where(Indicator.org_id == principal.org_id)
    if q:
        stmt = stmt.where(Indicator.value.ilike(f"%{q.strip().lower()}%"))
    if verdict:
        stmt = stmt.where(Indicator.analyst_verdict == verdict)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Indicator.last_looked_up.desc().nulls_last(), Indicator.first_seen.desc()).offset((page - 1) * page_size).limit(page_size)).scalars()
    return Page(items=[IndicatorOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


def _get(db: Session, principal: Principal, indicator_id: uuid.UUID) -> Indicator:
    ind = db.execute(select(Indicator).where(Indicator.id == indicator_id, Indicator.org_id == principal.org_id)).scalar_one_or_none()
    if ind is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ind


@router.get("/{indicator_id}")
def get_indicator(indicator_id: uuid.UUID, principal: Principal = Viewer, db: Session = Depends(get_db)) -> dict[str, Any]:
    ind = _get(db, principal, indicator_id)
    enrichments = db.execute(select(IndicatorEnrichment).where(IndicatorEnrichment.indicator_id == ind.id).order_by(IndicatorEnrichment.fetched_at.desc()).limit(50)).scalars()
    history = db.execute(
        select(IndicatorLookup, User.display_name)
        .outerjoin(User, User.id == IndicatorLookup.requested_by)
        .where(IndicatorLookup.indicator_id == ind.id, IndicatorLookup.org_id == principal.org_id)
        .order_by(IndicatorLookup.requested_at.desc())
        .limit(50)
    ).all()
    return {
        "indicator": IndicatorOut.model_validate(ind),
        "enrichments": [EnrichmentOut.model_validate(e) for e in enrichments],
        "history": [
            {"at": h.requested_at.isoformat(), "by": name, "incident_id": str(h.incident_id) if h.incident_id else None, "used_cache": h.used_cache} for h, name in history
        ],
        "local": intel.local_sightings(db, principal.org_id, ind.ioc_type, ind.value),
        "linked_incidents": intel.linked_incidents(db, principal.org_id, ind.id),
    }


@router.patch("/{indicator_id}", response_model=IndicatorOut)
def set_verdict(indicator_id: uuid.UUID, body: IocVerdictIn, principal: Principal = Analyst, ctx: RequestContext = Depends(get_ctx), db: Session = Depends(get_db)) -> IndicatorOut:
    """Record the analyst's conclusion, kept separate from provider-reported verdicts."""
    ind = _get(db, principal, indicator_id)
    previous = ind.analyst_verdict
    ind.analyst_verdict = body.analyst_verdict
    ind.analyst_note = body.analyst_note
    audit.record(db, ctx, "ioc.verdict_set", target_type="indicator", target_id=ind.id, details={"from": previous, "to": body.analyst_verdict, "note": body.analyst_note})
    db.commit()
    return IndicatorOut.model_validate(ind)
