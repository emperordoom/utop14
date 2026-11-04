"""Migration cycle tests for the security_events table."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask import Flask
from sqlalchemy import text
from sqlalchemy.engine import make_url

from app.extensions import db

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
