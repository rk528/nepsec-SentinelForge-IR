from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, Response
from sqlalchemy import text

from app.config import get_settings
from app.db import get_sessionmaker

router = APIRouter(tags=["health"])


@router.get("/health")
def health(response: Response) -> dict[str, object]:
    """Liveness plus a database round trip. Reveals no configuration details."""
    settings = get_settings()
    started = time.perf_counter()
    db_ok = False
    try:
        with get_sessionmaker()() as db:
            db.execute(text("SELECT 1"))
            db_ok = True
    except Exception:  # noqa: BLE001 - health must never raise
        db_ok = False
    if not db_ok:
        response.status_code = 503
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "unreachable",
        "database_latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "version": settings.app_version,
        "time": datetime.now(UTC).isoformat(),
    }
