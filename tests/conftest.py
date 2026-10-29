"""Shared pytest fixtures for UTOP14.

Database tests run only against the isolated PostgreSQL test database.  The
fixtures apply the real Alembic migrations, refuse databases whose name does not
end in ``_test``, and truncate only catalog tables between tests so the
development database is never touched.
"""

from __future__ import annotations

from collections.abc import Iterator
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

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR: Final = PROJECT_ROOT / "migrations"
CATALOG_TABLES: Final = ("product_images", "product_variants", "products", "categories")


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


def _truncate_catalog() -> None:
    """Remove catalog rows only, leaving the migration history intact."""
    db.session.rollback()
    db.session.execute(text(f"TRUNCATE TABLE {', '.join(CATALOG_TABLES)} RESTART IDENTITY CASCADE"))
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
        _truncate_catalog()
        try:
            yield _database_app
        finally:
            db.session.remove()
            _truncate_catalog()


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return a test client bound to the test application."""
    return app.test_client()


@pytest.fixture()
def seeded_catalog(app: Flask) -> SeedSummary:
    """Populate the launch catalog for storefront tests."""
    return seed_catalog()
