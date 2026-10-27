"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def build_engine(url: str) -> Engine:
    # Neon's pooled endpoint runs PgBouncer in transaction mode, so server-side
    # prepared statements are disabled (prepare_threshold=None). pool_pre_ping
    # recovers from connections dropped while the compute was suspended.
    return create_engine(
        url,
        pool_size=3,
        max_overflow=2,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args={"prepare_threshold": None, "connect_timeout": 10},
    )


@lru_cache
def get_engine() -> Engine:
    url = get_settings().database_url.get_secret_value()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")
    return build_engine(url)


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back on error."""
    db = get_sessionmaker()()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
