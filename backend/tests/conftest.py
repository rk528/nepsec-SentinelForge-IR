"""Test fixtures.

Tests run against a real PostgreSQL database (constraints, JSONB, triggers and
ON CONFLICT behaviour all matter here). Set TEST_DATABASE_URL to use an
existing server (CI uses a GitHub Actions service container); otherwise a
local server is started with pgserver, so no Docker is required.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        return url
    import pgserver

    data_dir = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".cache") / "sentinelforge-pgtest"
    server = pgserver.get_server(data_dir, cleanup_mode=None)
    server.psql("DROP DATABASE IF EXISTS sentinelforge_test WITH (FORCE);")
    server.psql("CREATE DATABASE sentinelforge_test;")
    return server.get_uri().rsplit("/", 1)[0] + "/sentinelforge_test"


DB_URL = _database_url()
os.environ.update(
    {
        "DATABASE_URL": DB_URL,
        "APP_ENV": "test",
        "COOKIE_SECURE": "false",
        "DEMO_MODE": "true",
        "TRUST_PROXY_HEADERS": "true",
        "CONSOLE_ORIGINS": "https://console.test",
    }
)
for key in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "NEPSECINTEL_API_KEY", "DATABASE_URL_UNPOOLED"):
    os.environ.pop(key, None)

from alembic.config import Config  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from alembic import command  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.db import get_sessionmaker  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Organization, User  # noqa: E402
from app.security import hash_password  # noqa: E402
from app.services import console_gate  # noqa: E402
from tests import helpers  # noqa: E402
from tests.helpers import PASSWORD, Api  # noqa: E402

# A key of the tests' own stands in for NepSec Intel's, so the console's passkey unlock can be signed here.
helpers.UNLOCK_KEY = ec.generate_private_key(ec.SECP256R1())
console_gate.set_key_for_tests(helpers.UNLOCK_KEY.public_key())
console_gate.KEY_SECONDS = 10**9


@pytest.fixture(scope="session", autouse=True)
def migrated() -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
def clean_db(migrated: None) -> Iterator[None]:
    yield
    with get_sessionmaker()() as db:
        tables = db.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'alembic_version'")).scalars().all()
        # TRUNCATE does not fire the row-level append-only trigger on audit_logs.
        db.execute(text("TRUNCATE " + ", ".join(f'"{t}"' for t in tables) + " CASCADE"))
        db.commit()
    get_settings.cache_clear()


@pytest.fixture
def db() -> Iterator[Session]:
    with get_sessionmaker()() as session:
        yield session


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def make_user(db: Session):
    orgs: dict[str, Organization] = {}

    def _make(role: str = "analyst", org: str = "acme", email: str | None = None) -> User:
        if org not in orgs:
            o = db.query(Organization).filter_by(slug=org).one_or_none()
            if o is None:
                o = Organization(name=f"{org.title()} SOC", slug=org)
                db.add(o)
                db.flush()
            orgs[org] = o
        u = User(
            org_id=orgs[org].id,
            email=email or f"{role}-{uuid.uuid4().hex[:6]}@{org}.test",
            display_name=f"{role.title()} {org}",
            role=role,
            password_hash=hash_password(PASSWORD),
        )
        db.add(u)
        db.commit()
        return u

    return _make


@pytest.fixture
def api_for(app, make_user):
    def _api(role: str = "analyst", org: str = "acme") -> Api:
        user = make_user(role, org)
        api = Api(TestClient(app)).login(user.email)
        # An administrator works user and data source administration from the admin console.
        return api.console_login(user.email) if role == "admin" else api

    return _api
