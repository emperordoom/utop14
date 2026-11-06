"""Integration tests for security-event retention holds and run-log foundation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.extensions import db
from app.models import (
    SecurityEvent,
    SecurityEventRetentionHold,
    SecurityEventRetentionRun,
)
from app.models.security_event import (
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_USER_REQUESTED,
)
from app.models.security_event_retention import (
    RETENTION_SCOPE_FAILURE,
    RETENTION_STATUS_STARTED,
    RETENTION_STATUS_SUCCESS,
)
from app.services.security_event_retention import (
    RetentionHoldExists,
    RetentionLocked,
    RetentionRunError,
    RetentionValidationError,
    create_hold,
    retention_policy,
)

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _add_event(*, created_at: datetime | None = None) -> SecurityEvent:
    event = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    if created_at is not None:
        event.created_at = created_at
    db.session.add(event)
    db.session.commit()
    return event


def _hold_count() -> int:
    return db.session.scalar(select(func.count(SecurityEventRetentionHold.id))) or 0


def test_retention_policy_defaults(app: Flask) -> None:
    policy = retention_policy()

    assert policy.success_days == 90
    assert policy.failure_days == 180
    assert policy.hold_max_days == 365
    assert policy.batch_size == 2000
    assert policy.max_batch_size == 5000
    assert policy.max_batches == 20


def test_active_hold_prevents_duplicate(app: Flask) -> None:
    event = _add_event()
    hold_id = create_hold(
        event_id=event.id,
        reason="incident investigation",
        created_by="operator-1",
        duration=timedelta(days=7),
    )

    hold = db.session.get(SecurityEventRetentionHold, hold_id)
    assert hold is not None
    assert hold.security_event_id == event.id
    assert hold.expires_at > datetime.now(UTC) + timedelta(days=6, hours=23)

    with pytest.raises(RetentionHoldExists):
        create_hold(
            event_id=event.id,
            reason="second hold",
            created_by="operator-2",
            duration=timedelta(days=8),
        )
    assert _hold_count() == 1


def test_expired_hold_can_be_replaced(app: Flask) -> None:
    event = _add_event()
    # A hold expires through the passage of database time.  Seed an already
    # expired row directly; the database trigger permits INSERT of an expired
    # hold while rejecting direct expiry of an active one.
    db.session.execute(
        text(
            "INSERT INTO security_event_retention_holds "
            "(security_event_id, reason, created_by, created_at, expires_at) "
            "VALUES (:event_id, 'temporary hold', 'operator-1', "
            "now() - interval '2 hours', now() - interval '1 hour')"
        ),
        {"event_id": event.id},
    )
    db.session.commit()
    first_id = db.session.scalar(
        select(SecurityEventRetentionHold.id).where(
            SecurityEventRetentionHold.security_event_id == event.id
        )
    )

    second_id = create_hold(
        event_id=event.id,
        reason="extended investigation",
        created_by="operator-2",
        duration=timedelta(days=2),
    )

    assert second_id == first_id
    hold = db.session.get(SecurityEventRetentionHold, first_id)
    assert hold is not None
    assert hold.reason == "extended investigation"
    assert hold.created_by == "operator-2"
    assert hold.expires_at > datetime.now(UTC) + timedelta(days=1, hours=23)
    assert _hold_count() == 1


def test_invalid_hold_values_are_rejected(app: Flask) -> None:
    event = _add_event()

    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="bad @ email",
            created_by="operator",
            duration=timedelta(days=1),
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator@example.com",
            duration=timedelta(days=1),
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator",
            duration=timedelta(0),
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator",
            duration=timedelta(days=400),
        )
    assert _hold_count() == 0


@pytest.mark.parametrize(
    "reason",
    [
        "investigate 203.0.113.10",
        "client [2001:db8::1] reported",
        "seen at 198.51.100.7, keep",
        "host (192.0.2.44)",
    ],
)
def test_hold_reason_rejects_ip_literals(app: Flask, reason: str) -> None:
    event = _add_event()

    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason=reason,
            created_by="operator",
            duration=timedelta(days=1),
        )
    assert _hold_count() == 0


def test_hold_reason_accepts_non_ip_text(app: Flask) -> None:
    event = _add_event()

    hold_id = create_hold(
        event_id=event.id,
        reason="investigate suspicious account activity",
        created_by="operator",
        duration=timedelta(days=1),
    )

    assert db.session.get(SecurityEventRetentionHold, hold_id) is not None


def test_retention_run_log_constraints(app: Flask) -> None:
    row = SecurityEventRetentionRun(
        run_id="run-1",
        batch_index=0,
        scope=RETENTION_SCOPE_FAILURE,
        cutoff=NOW,
        deleted_count=2,
        status=RETENTION_STATUS_SUCCESS,
        executed_by="test-suite",
        started_at=NOW,
        finished_at=NOW,
    )
    db.session.add(row)
    db.session.commit()
    assert row.id is not None

    invalid = SecurityEventRetentionRun(
        run_id="run-2",
        batch_index=0,
        scope=RETENTION_SCOPE_FAILURE,
        cutoff=NOW,
        deleted_count=0,
        status="unknown",
        executed_by="test-suite",
        started_at=NOW,
        finished_at=NOW,
    )
    db.session.add(invalid)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_retention_cli_requires_runner_dsn(app: Flask) -> None:
    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "run"],
    )

    assert result.exit_code == 1
    assert "SECURITY_EVENT_RETENTION_DATABASE_URL" in result.output


class _FakeResult:
    def __init__(self, *, scalar_value=None, scalar_one_value=None):
        self._scalar_value = scalar_value
        self._scalar_one_value = scalar_one_value

    def scalar(self):
        return self._scalar_value

    def scalar_one(self):
        return self._scalar_one_value


class _FakeConnection:
    def __init__(self, *, fail_abandon: bool = False, deletes: list[int] | None = None):
        self._fail_abandon = fail_abandon
        self._deletes = deletes

    def execute(self, statement, params=None):
        sql = str(statement)
        if "pg_try_advisory_lock" in sql:
            return _FakeResult(scalar_value=True)
        if "SELECT now()" in sql:
            return _FakeResult(scalar_one_value=datetime.now(UTC))
        if "pg_advisory_unlock" in sql:
            return _FakeResult()
        if "begin_retention_run" in sql:
            return _FakeResult()
        if "prune_security_events" in sql:
            if self._deletes is None:
                raise SQLAlchemyError("batch failed")
            return _FakeResult(scalar_one_value=self._deletes.pop(0))
        if "abandon_retention_run" in sql:
            if self._fail_abandon:
                raise SQLAlchemyError("abandon failed")
            return _FakeResult()
        raise SQLAlchemyError("unexpected statement")

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _FakeEngine:
    def __init__(
        self,
        *,
        fail_abandon: bool = False,
        deletes: list[int] | None = None,
    ):
        self._fail_abandon = fail_abandon
        self._deletes = deletes

    def connect(self):
        return _FakeConnection(fail_abandon=self._fail_abandon, deletes=self._deletes)

    def begin(self):
        return _FakeConnection(fail_abandon=self._fail_abandon, deletes=self._deletes)


class _ConnectFailureEngine:
    def __init__(self, error: SQLAlchemyError):
        self._error = error

    def connect(self):
        raise self._error


class _InitialFailureConnection:
    def __init__(self, fail_on: str):
        self._fail_on = fail_on

    def execute(self, statement, params=None):
        sql = str(statement)
        if self._fail_on in sql:
            raise SQLAlchemyError("sensitive driver detail")
        if "pg_try_advisory_lock" in sql:
            return _FakeResult(scalar_value=True)
        if "SELECT now()" in sql:
            return _FakeResult(scalar_one_value=datetime.now(UTC))
        if "pg_advisory_unlock" in sql:
            return _FakeResult()
        raise SQLAlchemyError("unexpected statement")

    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _InitialFailureEngine:
    def __init__(self, fail_on: str):
        self._fail_on = fail_on

    def connect(self):
        return _InitialFailureConnection(self._fail_on)

    def begin(self):
        return _InitialFailureConnection(self._fail_on)


def test_initial_connect_failure_is_safe(app: Flask) -> None:
    from app.services import security_event_retention as service

    error = SQLAlchemyError("sensitive postgresql://user:secret@db-host/utop14")
    with pytest.raises(RetentionRunError) as exc_info:
        service.run_retention(_ConnectFailureEngine(error))

    message = str(exc_info.value)
    assert "Unable to connect" in message
    assert "postgresql" not in message.lower()
    assert "secret" not in message.lower()
    assert "db-host" not in message.lower()


@pytest.mark.parametrize("fail_on", ["pg_try_advisory_lock", "SELECT now()"])
def test_initial_retention_query_failure_is_safe(app: Flask, fail_on: str) -> None:
    from app.services import security_event_retention as service

    with pytest.raises(RetentionRunError, match="Unable to initialize") as exc_info:
        service.run_retention(_InitialFailureEngine(fail_on))

    assert "sensitive driver detail" not in str(exc_info.value)


def test_run_retention_success_uses_one_db_cutoff_per_scope(app: Flask) -> None:
    from app.services import security_event_retention as service

    summary = service.run_retention(_FakeEngine(deletes=[0, 0]))

    assert summary.status == "success"
    assert summary.batch_count == 2
    assert summary.deleted_count == 0


def test_run_retention_partial_when_batch_budget_exhausted(app: Flask) -> None:
    from app.services import security_event_retention as service

    summary = service.run_retention(
        _FakeEngine(deletes=[2000]),
        batch_size=2000,
        max_batches=1,
    )

    assert summary.status == "partial"
    assert summary.batch_count == 1


def test_failed_batch_is_abandoned_without_success(
    app: Flask,
) -> None:
    from app.services import security_event_retention as service

    with pytest.raises(RetentionRunError, match="batch failed"):
        service.run_retention(_FakeEngine())


def test_failed_abandon_is_normalized(
    app: Flask,
) -> None:
    from app.services import security_event_retention as service

    with pytest.raises(RetentionRunError, match="could not be logged"):
        service.run_retention(_FakeEngine(fail_abandon=True))


def test_cli_normalizes_retention_run_error_without_traceback(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.cli as cli_module

    app.config["SECURITY_EVENT_RETENTION_DATABASE_URL"] = "postgresql+psycopg://user@127.0.0.1:1/db"

    def fail_run(*_args, **_kwargs):
        raise RetentionRunError("safe retention failure")

    monkeypatch.setattr(cli_module, "run_retention", fail_run)

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "run"],
    )

    assert result.exit_code == 1
    assert "safe retention failure" in result.output
    assert "Traceback" not in result.output


def test_cli_initial_database_error_does_not_leak_credentials(app: Flask) -> None:
    sentinel = "review-sentinel-password-123"
    app.config["SECURITY_EVENT_RETENTION_DATABASE_URL"] = (
        f"postgresql+psycopg://runner:{sentinel}@127.0.0.1:1/utop14_test"
    )

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "run"],
    )

    assert result.exit_code == 1
    assert sentinel not in result.output
    assert "postgresql+psycopg" not in result.output
    assert "127.0.0.1" not in result.output
    assert "Unable to connect" in result.output
    assert db.session.scalar(select(func.count(SecurityEventRetentionRun.id))) == 0


def test_cli_orphan_detection_finds_started_run(app: Flask) -> None:
    app.config["SECURITY_EVENT_RETENTION_DATABASE_URL"] = app.config["SQLALCHEMY_DATABASE_URI"]
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=100)
    old_run = SecurityEventRetentionRun(
        run_id="orphan-old-run",
        batch_index=0,
        scope=RETENTION_SCOPE_FAILURE,
        cutoff=cutoff,
        deleted_count=0,
        status=RETENTION_STATUS_STARTED,
        executed_by="test-suite",
        started_at=now - timedelta(hours=2),
        finished_at=None,
    )
    recent_run = SecurityEventRetentionRun(
        run_id="orphan-recent-run",
        batch_index=1,
        scope=RETENTION_SCOPE_FAILURE,
        cutoff=cutoff,
        deleted_count=0,
        status=RETENTION_STATUS_STARTED,
        executed_by="test-suite",
        started_at=now - timedelta(minutes=5),
        finished_at=None,
    )
    db.session.add_all([old_run, recent_run])
    db.session.commit()

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "orphans", "--older-than-minutes", "60"],
    )

    assert result.exit_code == 0
    assert "orphan-old-run" in result.output
    assert "orphan-recent-run" not in result.output


def test_cli_lock_contention_keeps_exit_code_three(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.cli as cli_module

    app.config["SECURITY_EVENT_RETENTION_DATABASE_URL"] = app.config["SQLALCHEMY_DATABASE_URI"]

    def locked(*_args, **_kwargs):
        raise RetentionLocked("another run is active")

    monkeypatch.setattr(cli_module, "run_retention", locked)

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "run"],
    )

    assert result.exit_code == 3
    assert "already running" in result.output


def test_cli_malformed_runner_dsn_is_safe(app: Flask) -> None:
    sentinel = "review-sentinel-malformed-dsn"
    app.config["SECURITY_EVENT_RETENTION_DATABASE_URL"] = (
        f"postgresql+psycopg://runner:{sentinel}@["
    )

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "run"],
    )

    assert result.exit_code == 1
    assert (
        "Unable to configure the retention database connection." in result.output
        or "Unable to connect to the retention database." in result.output
    )
    assert sentinel not in result.output
