"""Regression tests for M14.3.3.2 retention hardening.

These tests exercise the database-level hold lock trigger and the hardened
retention function validation on the regular test database.  The full
concurrency/ownership suite runs separately on a disposable PostgreSQL cluster.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.extensions import db
from app.models import SecurityEvent, SecurityEventRetentionHold
from app.models.security_event import (
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_USER_REQUESTED,
)


def _add_event() -> SecurityEvent:
    event = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    db.session.add(event)
    db.session.commit()
    return event


def _add_hold(
    event_id: int,
    *,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SecurityEventRetentionHold:
    now = datetime.now(UTC)
    hold = SecurityEventRetentionHold(
        security_event_id=event_id,
        reason="investigation",
        created_by="operator",
        created_at=created_at or now,
        expires_at=expires_at or (now + timedelta(days=1)),
    )
    db.session.add(hold)
    db.session.commit()
    return hold


def test_function_rejects_null_scope(app: Flask) -> None:
    with pytest.raises(DBAPIError) as error:
        db.session.execute(
            text(
                "SELECT public.prune_security_events("
                "NULL, now() - interval '200 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, 0)"
            )
        )
    db.session.rollback()
    assert "invalid retention scope" in str(error.value)


@pytest.mark.parametrize("index", [100, 101, -1])
def test_function_rejects_out_of_range_batch_index(app: Flask, index: int) -> None:
    with pytest.raises(DBAPIError) as error:
        db.session.execute(
            text(
                "SELECT public.prune_security_events("
                "'success_logout', now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, :index)"
            ),
            {"index": index},
        )
    db.session.rollback()
    assert "invalid retention batch index" in str(error.value)


def test_function_rejects_null_batch_index(app: Flask) -> None:
    with pytest.raises(DBAPIError) as error:
        db.session.execute(
            text(
                "SELECT public.prune_security_events("
                "'success_logout', now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, NULL)"
            )
        )
    db.session.rollback()
    assert "invalid retention batch index" in str(error.value)


@pytest.mark.parametrize("index", [0, 99])
def test_function_accepts_valid_batch_index_boundaries(app: Flask, index: int) -> None:
    try:
        db.session.execute(
            text(
                "SELECT public.prune_security_events("
                "'success_logout', now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, :index)"
            ),
            {"index": index},
        )
        db.session.commit()
    except DBAPIError as error:
        db.session.rollback()
        # The unprovisioned test database still rejects the DELETE through the
        # append-only trigger.  The index boundary itself must be accepted.
        assert "invalid retention batch index" not in str(error)


def test_hold_trigger_rejects_expiring_active_hold(app: Flask) -> None:
    event = _add_event()
    _add_hold(event.id)

    with pytest.raises(DBAPIError) as error:
        db.session.execute(
            text(
                "UPDATE security_event_retention_holds "
                "SET created_at = now() - interval '2 hours', "
                "expires_at = now() - interval '1 hour' "
                "WHERE security_event_id = :event_id"
            ),
            {"event_id": event.id},
        )
        db.session.commit()
    db.session.rollback()

    assert "active investigative holds cannot be expired or shortened" in str(error.value)
    hold = db.session.scalar(
        select(SecurityEventRetentionHold).where(
            SecurityEventRetentionHold.security_event_id == event.id
        )
    )
    assert hold is not None
    assert hold.expires_at > datetime.now(UTC)


def test_hold_trigger_allows_moving_to_another_event(app: Flask) -> None:
    first = _add_event()
    second = _add_event()
    hold = _add_hold(first.id)

    db.session.execute(
        text(
            "UPDATE security_event_retention_holds "
            "SET security_event_id = :second WHERE id = :hold_id"
        ),
        {"second": second.id, "hold_id": hold.id},
    )
    db.session.commit()

    moved = db.session.get(SecurityEventRetentionHold, hold.id)
    assert moved is not None
    assert moved.security_event_id == second.id


def test_hold_trigger_allows_replacing_expired_hold(app: Flask) -> None:
    event = _add_event()
    now = datetime.now(UTC)
    hold = _add_hold(
        event.id,
        created_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )

    db.session.execute(
        text(
            "UPDATE security_event_retention_holds "
            "SET created_at = now(), expires_at = now() + interval '2 days' "
            "WHERE id = :hold_id"
        ),
        {"hold_id": hold.id},
    )
    db.session.commit()

    replaced = db.session.get(SecurityEventRetentionHold, hold.id)
    assert replaced is not None
    assert replaced.expires_at > datetime.now(UTC)


def test_hold_trigger_rejects_excessive_duration(app: Flask) -> None:
    event = _add_event()

    with pytest.raises(DBAPIError) as error:
        db.session.execute(
            text(
                "INSERT INTO security_event_retention_holds "
                "(security_event_id, reason, created_by, created_at, expires_at) "
                "VALUES (:event_id, 'too long', 'operator', now(), "
                "now() + interval '3651 days')"
            ),
            {"event_id": event.id},
        )
        db.session.commit()
    db.session.rollback()

    assert "hold expiry exceeds the maximum allowed duration" in str(error.value)
