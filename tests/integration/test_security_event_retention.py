"""Integration tests for security-event retention holds and run-log foundation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

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
    RETENTION_STATUS_SUCCESS,
)
from app.services.security_event_retention import (
    RetentionHoldExists,
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
        expires_at=NOW + timedelta(days=7),
        now=NOW,
    )

    hold = db.session.get(SecurityEventRetentionHold, hold_id)
    assert hold is not None
    assert hold.security_event_id == event.id
    assert hold.expires_at == NOW + timedelta(days=7)

    with pytest.raises(RetentionHoldExists):
        create_hold(
            event_id=event.id,
            reason="second hold",
            created_by="operator-2",
            expires_at=NOW + timedelta(days=8),
            now=NOW,
        )
    assert _hold_count() == 1


def test_expired_hold_can_be_replaced(app: Flask) -> None:
    event = _add_event()
    first_id = create_hold(
        event_id=event.id,
        reason="temporary hold",
        created_by="operator-1",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )

    second_id = create_hold(
        event_id=event.id,
        reason="extended investigation",
        created_by="operator-2",
        expires_at=NOW + timedelta(days=2),
        now=NOW + timedelta(hours=2),
    )

    assert second_id == first_id
    hold = db.session.get(SecurityEventRetentionHold, first_id)
    assert hold is not None
    assert hold.reason == "extended investigation"
    assert hold.created_by == "operator-2"
    assert _hold_count() == 1


def test_invalid_hold_values_are_rejected(app: Flask) -> None:
    event = _add_event()

    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="bad @ email",
            created_by="operator",
            expires_at=NOW + timedelta(days=1),
            now=NOW,
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator@example.com",
            expires_at=NOW + timedelta(days=1),
            now=NOW,
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator",
            expires_at=NOW,
            now=NOW,
        )
    with pytest.raises(RetentionValidationError):
        create_hold(
            event_id=event.id,
            reason="valid reason",
            created_by="operator",
            expires_at=NOW + timedelta(days=400),
            now=NOW,
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
            expires_at=NOW + timedelta(days=1),
            now=NOW,
        )
    assert _hold_count() == 0


def test_hold_reason_accepts_non_ip_text(app: Flask) -> None:
    event = _add_event()

    hold_id = create_hold(
        event_id=event.id,
        reason="investigate suspicious account activity",
        created_by="operator",
        expires_at=NOW + timedelta(days=1),
        now=NOW,
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
