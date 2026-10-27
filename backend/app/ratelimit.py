"""Postgres-backed fixed-window rate limiting.

Serverless instances do not share memory, so counters live in the database.
A single upsert statement makes increments atomic under concurrency.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

_UPSERT = text(
    """
    INSERT INTO rate_limit_buckets (key, window_start, count)
    VALUES (:key, :now, 1)
    ON CONFLICT (key) DO UPDATE SET
        count = CASE WHEN rate_limit_buckets.window_start < :cutoff THEN 1 ELSE rate_limit_buckets.count + 1 END,
        window_start = CASE WHEN rate_limit_buckets.window_start < :cutoff THEN :now ELSE rate_limit_buckets.window_start END
    RETURNING count, window_start
    """
)


def hit(db: Session, key: str, limit: int, window_seconds: int) -> None:
    """Count one request against ``key``; raise 429 when the limit is exceeded.

    The counter is committed independently of the caller's transaction so a
    failed request (for example a wrong password) still counts.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=window_seconds)
    row = db.execute(_UPSERT, {"key": key[:200], "now": now, "cutoff": cutoff}).one()
    db.commit()
    count, window_start = row
    if count > limit:
        retry_after = max(1, int((window_start + timedelta(seconds=window_seconds) - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
