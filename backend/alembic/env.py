"""Alembic environment.

Migrations use the direct (unpooled) Neon connection when available, because
DDL through PgBouncer in transaction mode is unreliable.
"""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context
from app import models  # noqa: F401 - registers tables on Base.metadata
from app.config import get_settings
from app.db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    override = config.attributes.get("database_url")
    if override:
        return override
    s = get_settings()
    url = (s.database_url_unpooled or s.database_url).get_secret_value()
    if not url:
        raise RuntimeError("Set DATABASE_URL_UNPOOLED or DATABASE_URL before running migrations")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
