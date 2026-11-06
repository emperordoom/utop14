"""Shared pytest fixtures for UTOP14.

Database tests run only against the isolated PostgreSQL test database.  The
fixtures apply the real Alembic migrations, refuse databases whose name does not
end in ``_test``, and truncate account and catalog tables between tests so the
development database is never touched.

The suite uses one shared test database.  Do not run concurrent pytest processes
(including pytest-xdist) against the same database: fixtures truncate shared
tables and the migration-cycle test mutates the schema for one test.
"""

from __future__ import annotations

import re
import secrets
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Final

import pytest
from alembic import command
from alembic.config import Config
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select, text
from sqlalchemy.engine import make_url

from app import create_app
from app.catalog.seed import SeedSummary, seed_catalog
from app.extensions import db
from app.models import Order, Payment, ProductVariant, User
from app.models.user import ROLE_CUSTOMER
from app.services.cart import add_to_cart
from app.services.checkout import checkout
from app.services.payments import create_payment_attempt

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR: Final = PROJECT_ROOT / "migrations"
_TEST_SECURITY_EVENT_HASH_KEY: Final = secrets.token_urlsafe(48)
CONSTRAINED_POOL_OPTIONS: Final = {
    "pool_pre_ping": True,
    "pool_size": 1,
    "max_overflow": 0,
    "pool_timeout": 1,
}
RESET_TABLES: Final = (
    "admin_security_event_filter_states",
    "security_event_retention_holds",
    "security_event_retention_runs",
    "auth_rate_limits",
    "security_events",
    "audit_logs",
    "product_reviews",
    "payment_proofs",
    "payments",
    "order_items",
    "orders",
    "cart_items",
    "carts",
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
def _database_app(tmp_path_factory: pytest.TempPathFactory) -> Flask:
    """Create the shared test application and migrate the test database once."""
    avatar_storage_path = tmp_path_factory.mktemp("avatars")
    application = create_app(
        "testing",
        {
            "AVATAR_STORAGE_PATH": str(avatar_storage_path),
            "SECURITY_EVENT_HASH_KEY": _TEST_SECURITY_EVENT_HASH_KEY,
        },
    )
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
def no_ambient_security_event_hash_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove an ambient HMAC key so app-creation tests stay deterministic."""
    monkeypatch.delenv("SECURITY_EVENT_HASH_KEY", raising=False)


@pytest.fixture()
def constrained_pool_app(
    _database_app: Flask,
    tmp_path: Path,
) -> Iterator[Flask]:
    """Application on the isolated test DB with a one-connection pool."""
    application = create_app(
        "testing",
        {
            "AVATAR_STORAGE_PATH": str(tmp_path / "avatars"),
            "SECURITY_EVENT_HASH_KEY": _TEST_SECURITY_EVENT_HASH_KEY,
            "SQLALCHEMY_ENGINE_OPTIONS": dict(CONSTRAINED_POOL_OPTIONS),
        },
    )
    _assert_test_database(application)
    with application.app_context():
        _reset_tables()
        try:
            yield application
        finally:
            db.session.remove()
            _reset_tables()
            db.engine.dispose()


@pytest.fixture()
def avatar_storage(
    app: Flask,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Use an isolated avatar directory and remove it after the test."""
    storage = tmp_path / "avatars"
    monkeypatch.setitem(app.config, "AVATAR_STORAGE_PATH", str(storage))
    try:
        yield storage
    finally:
        shutil.rmtree(storage, ignore_errors=True)


@pytest.fixture()
def payment_proof_storage(
    app: Flask,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Use an isolated payment-proof directory and remove it after the test."""
    storage = tmp_path / "payment-proofs"
    monkeypatch.setitem(app.config, "PAYMENT_PROOF_STORAGE_PATH", str(storage))
    try:
        yield storage
    finally:
        shutil.rmtree(storage, ignore_errors=True)


@pytest.fixture()
def bank_transfer_config(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, str]:
    """Configure dummy bank details for manual-transfer tests."""
    values = {
        "BANK_TRANSFER_BANK_NAME": "Test Bank",
        "BANK_TRANSFER_ACCOUNT_NAME": "UTOP14 Test Account",
        "BANK_TRANSFER_ACCOUNT_NUMBER": "0000000000",
    }
    for key, value in values.items():
        monkeypatch.setitem(app.config, key, value)
    return values


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


@pytest.fixture()
def database_timezone(app: Flask) -> Iterator[Callable[[str], None]]:
    """Set the PostgreSQL session timezone and restore it after the test.

    The app fixture keeps one scoped session for the test, so setting the
    session timezone affects the same connection used by test-client requests.
    The previous value is restored even when an assertion fails.
    """
    previous = db.session.execute(text("SHOW timezone")).scalar_one()

    def _set_timezone(name: str) -> None:
        db.session.execute(
            text("SELECT set_config('TimeZone', :name, false)"),
            {"name": name},
        )

    try:
        yield _set_timezone
    finally:
        db.session.rollback()
        db.session.execute(
            text("SELECT set_config('TimeZone', :name, false)"),
            {"name": previous},
        )
        db.session.rollback()


@pytest.fixture()
def login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> Callable[..., object]:
    """Log the test client in as an existing account."""

    def _login(
        email: str,
        password: str = "ValidPass123",
        *,
        follow_redirects: bool = False,
    ) -> object:
        response = client.post(
            "/auth/login",
            data={
                "csrf_token": csrf_token("/auth/login"),
                "email": email,
                "password": password,
            },
            follow_redirects=follow_redirects,
        )
        if response.status_code != 302:
            raise AssertionError(f"Login failed for {email}: {response.status_code}")
        return response

    return _login


@pytest.fixture()
def make_order(
    app: Flask,
    seeded_catalog: SeedSummary,
) -> Callable[..., Order]:
    """Create a committed order for a test user through real checkout."""

    def _make_order(
        user: User,
        *,
        sku: str = "UT014-VT-WBK-M",
        quantity: int = 1,
        status: str | None = None,
        payment_status: str | None = None,
    ) -> Order:
        variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
        if variant is None:
            raise AssertionError(f"Missing seed variant: {sku}")

        add_to_cart(user.id, variant.id, quantity)
        order = checkout(
            user.id,
            recipient_name=user.full_name,
            recipient_phone="+1 555 0100",
            shipping_address="14 After Hours Street",
            shipping_city="Night City",
            shipping_postal_code="01400",
        )

        if status is not None:
            order.status = status
        if payment_status is not None:
            order.payment_status = payment_status
        if status is not None or payment_status is not None:
            db.session.commit()

        return order

    return _make_order


@pytest.fixture()
def make_payment(
    app: Flask,
    make_order: Callable[..., Order],
) -> Callable[..., Payment]:
    """Create a committed pending simulated payment for a test order."""

    def _make_payment(
        user: User,
        *,
        order: Order | None = None,
        idempotency_key: str | None = None,
    ) -> Payment:
        target_order = order or make_order(user)
        return create_payment_attempt(
            user.id,
            target_order.order_number,
            idempotency_key or secrets.token_urlsafe(24),
        )

    return _make_payment
