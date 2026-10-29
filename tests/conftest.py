"""Shared pytest fixtures for UTOP14.

Database tests run only against the isolated PostgreSQL test database.  The
fixtures apply the real Alembic migrations, refuse databases whose name does not
end in ``_test``, and truncate account and catalog tables between tests so the
development database is never touched.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Final

import pytest
from alembic import command
from alembic.config import Config
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app import create_app
from app.catalog.seed import SeedSummary, seed_catalog
from app.extensions import db
from app.models import User
from app.models.user import ROLE_CUSTOMER

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR: Final = PROJECT_ROOT / "migrations"
RESET_TABLES: Final = (
    "users",
    "product_images",
    "product_variants",
    "products",
    "categories",
)


def _database_name(application: Flask) -> str:
    """Return the configured database name without exposing credentials."""
    return make_url(str(application.config["SQLALCHEMY_DATABASE_URI"])).database or ""


def _assert_test_database(application: Flask) -> None:
    """Fail fast before any test can touch a non-test database."""
    database_url = str(application.config["SQLALCHEMY_DATABASE_URI"])
    if not database_url.startswith("postgresql+psycopg://"):
        raise RuntimeError("The test suite requires PostgreSQL via the psycopg 3 driver.")
    if not _database_name(application).endswith("_test"):
        raise RuntimeError("The test database name must end with '_test'.")


def _run_migrations(application: Flask) -> None:
    """Apply the committed migrations to the isolated test database."""
    alembic_config = Config(str(MIGRATIONS_DIR / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(MIGRATIONS_DIR))
    with application.app_context():
        command.upgrade(alembic_config, "head")


def _reset_tables() -> None:
    """Remove account and catalog rows, leaving migration history intact."""
    db.session.rollback()
    db.session.execute(text(f"TRUNCATE TABLE {', '.join(RESET_TABLES)} RESTART IDENTITY CASCADE"))
    db.session.commit()


@pytest.fixture(scope="session")
def _database_app() -> Flask:
    """Create the shared test application and migrate the test database once."""
    application = create_app("testing")
    _assert_test_database(application)
    _run_migrations(application)
    return application


@pytest.fixture()
def app(_database_app: Flask) -> Iterator[Flask]:
    """Return a clean application context backed by the migrated test database."""
    with _database_app.app_context():
        _reset_tables()
        try:
            yield _database_app
        finally:
            db.session.remove()
            _reset_tables()


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return a test client bound to the test application."""
    return app.test_client()


@pytest.fixture()
def seeded_catalog(app: Flask) -> SeedSummary:
    """Populate the launch catalog for storefront tests."""
    return seed_catalog()


@pytest.fixture()
def make_user(app: Flask) -> Callable[..., User]:
    """Return a factory that creates committed test accounts."""

    def _make_user(
        *,
        email: str = "customer@example.com",
        password: str = "ValidPass123",
        full_name: str = "Test Customer",
        role: str = ROLE_CUSTOMER,
        is_active: bool = True,
    ) -> User:
        user = User(
            email=email,
            full_name=full_name,
            role=role,
            is_active=is_active,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    return _make_user


@pytest.fixture()
def csrf_token(client: FlaskClient) -> Callable[[str], str]:
    """Return a helper that extracts a CSRF token from a rendered page."""

    def _csrf_token(path: str) -> str:
        response = client.get(path)
        if response.status_code != 200:
            raise AssertionError(f"Expected 200 from {path}, got {response.status_code}")

        html = response.get_data(as_text=True)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        if match is None:
            raise AssertionError(f"No CSRF token found at {path}")
        return match.group(1)

    return _csrf_token
