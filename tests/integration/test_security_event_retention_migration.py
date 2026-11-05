"""Migration tests for security-event retention tables and trigger function."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from flask import Flask
from sqlalchemy import text

from app.extensions import db
from app.models import SecurityEventRetentionRun
from app.models.security_event_retention import (
    RETENTION_SCOPE_FAILURE,
    RETENTION_STATUS_SUCCESS,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    config = Config(str(PROJECT_ROOT / "migrations" / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return config


def _table_exists(name: str) -> bool:
    return bool(
        db.session.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"),
            {"name": f"public.{name}"},
        ).scalar()
    )


def _function_exists(name: str) -> bool:
    return bool(
        db.session.execute(
            text("SELECT to_regprocedure(:name) IS NOT NULL"),
            {"name": f"public.{name}"},
        ).scalar()
    )


def _trigger_exists(table: str, trigger: str) -> bool:
    return bool(
        db.session.execute(
            text(
                "SELECT EXISTS ("
                "SELECT 1 FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relname = :table "
                "AND t.tgname = :trigger AND NOT t.tgisinternal)"
            ),
            {"table": table, "trigger": trigger},
        ).scalar()
    )


def test_retention_migration_upgrade_and_downgrade(app: Flask) -> None:
    config = _alembic_config()
    head = ScriptDirectory.from_config(config).get_current_head()
    assert head is not None

    try:
        command.downgrade(config, "b4d8e2f7a1c9")
        db.session.remove()
        assert _table_exists("security_event_retention_holds") is False
        assert _table_exists("security_event_retention_runs") is False
        assert (
            _function_exists("prune_security_events(text, timestamptz, integer, uuid, integer)")
            is False
        )

        command.upgrade(config, "head")
        db.session.remove()
        assert _table_exists("security_event_retention_holds") is True
        assert _table_exists("security_event_retention_runs") is True
        assert (
            _function_exists("prune_security_events(text, timestamptz, integer, uuid, integer)")
            is True
        )
        assert (
            _trigger_exists(
                "security_event_retention_holds",
                "security_event_retention_holds_lock",
            )
            is True
        )
        assert _function_exists("security_event_retention_holds_lock()") is True
    finally:
        command.upgrade(config, "head")
        db.session.remove()


def test_retention_hardening_downgrade_keeps_tables_and_retention_function(
    app: Flask,
) -> None:
    config = _alembic_config()
    try:
        command.downgrade(config, "d7c1a9e4b2f8")
        db.session.remove()
        assert (
            _trigger_exists(
                "security_event_retention_holds",
                "security_event_retention_holds_lock",
            )
            is False
        )
        assert _function_exists("security_event_retention_holds_lock()") is False
        assert _table_exists("security_event_retention_holds") is True
        assert _table_exists("security_event_retention_runs") is True
        assert (
            _function_exists("prune_security_events(text, timestamptz, integer, uuid, integer)")
            is True
        )
    finally:
        command.upgrade(config, "head")
        db.session.remove()


def test_retention_downgrade_refuses_existing_run_history(app: Flask) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    row = SecurityEventRetentionRun(
        run_id="downgrade-guard",
        batch_index=0,
        scope=RETENTION_SCOPE_FAILURE,
        cutoff=now,
        deleted_count=0,
        status=RETENTION_STATUS_SUCCESS,
        started_at=now,
        finished_at=now,
    )
    db.session.add(row)
    db.session.commit()

    config = _alembic_config()
    try:
        with pytest.raises(RuntimeError, match="Refusing to downgrade"):
            command.downgrade(config, "b4d8e2f7a1c9")
    finally:
        db.session.rollback()
        db.session.execute(text("DELETE FROM security_event_retention_runs"))
        db.session.commit()
        command.upgrade(config, "head")
        db.session.remove()
