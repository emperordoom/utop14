"""Migration cycle tests for the PostgreSQL rate-limit table."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask import Flask
from sqlalchemy import text

from app.extensions import db

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    config = Config(str(PROJECT_ROOT / "migrations" / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return config


def _table_exists() -> bool:
    return bool(
        db.session.execute(
            text("SELECT to_regclass('public.auth_rate_limits') IS NOT NULL")
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


def _constraint_exists(name: str) -> bool:
    return bool(
        db.session.execute(
            text(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_constraint "
                "WHERE conname = :name AND conrelid = 'auth_rate_limits'::regclass"
                ")"
            ),
            {"name": name},
        ).scalar()
    )


def test_auth_rate_limit_migration_downgrade_and_upgrade(app: Flask) -> None:
    config = _alembic_config()
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None

    try:
        command.downgrade(config, "c4e7a1b9d2f6")
        db.session.remove()
        assert _table_exists() is False

        command.upgrade(config, "head")
        db.session.remove()
        assert _table_exists() is True
        assert _index_exists("ix_auth_rate_limits_updated_at") is True
        assert _constraint_exists("auth_rate_limit_scope_valid") is True
        assert _constraint_exists("auth_rate_limit_key_hash_length") is True
        assert _revision() == head
    finally:
        command.upgrade(config, "head")
        db.session.remove()
