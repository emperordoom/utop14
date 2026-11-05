"""Migration cycle tests for the security_events table."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask import Flask
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.models import SecurityEvent
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_THROTTLED,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    config = Config(str(PROJECT_ROOT / "migrations" / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return config


def _table_exists() -> bool:
    return bool(
        db.session.execute(
            text("SELECT to_regclass('public.security_events') IS NOT NULL")
        ).scalar()
    )


def _index_exists(name: str) -> bool:
    return bool(
        db.session.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"),
            {"name": f"public.{name}"},
        ).scalar()
    )


def _revision() -> str | None:
    value = db.session.execute(text("SELECT version_num FROM alembic_version")).scalar()
    return str(value) if value is not None else None


def _throttled_event() -> SecurityEvent:
    return SecurityEvent(
        event_type=SECURITY_EVENT_LOGIN_THROTTLED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={
            "scope": "identifier",
            "retry_after_seconds": 60,
            "window_seconds": 900,
            "failure_count": 5,
        },
    )


def test_security_event_migration_downgrade_and_upgrade(app: Flask) -> None:
    url = make_url(str(app.config["SQLALCHEMY_DATABASE_URI"]))
    assert (url.database or "").endswith("_test")

    config = _alembic_config()
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None

    with app.app_context():
        try:
            command.downgrade(config, "3f7a2c9d1b64")
            db.session.remove()
            assert _table_exists() is False

            command.upgrade(config, "head")
            db.session.remove()
            assert _table_exists() is True
            assert _index_exists("ix_security_events_request_id") is True
            assert _revision() == head
        finally:
            command.upgrade(config, "head")
            db.session.remove()


def test_login_throttled_event_type_migration(app: Flask) -> None:
    config = _alembic_config()
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None

    try:
        command.downgrade(config, "e1b7c4a9d2f3")
        db.session.remove()

        db.session.add(_throttled_event())
        with pytest.raises(SQLAlchemyError):
            db.session.commit()
        db.session.rollback()

        command.upgrade(config, "head")
        db.session.remove()

        event = _throttled_event()
        db.session.add(event)
        db.session.commit()
        assert event.id is not None
        assert _revision() == head
    finally:
        command.upgrade(config, "head")
        db.session.remove()
