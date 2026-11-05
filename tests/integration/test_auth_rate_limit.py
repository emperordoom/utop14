"""Integration tests for the PostgreSQL authentication rate-limit store."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.extensions import db
from app.models import AuthRateLimit, SecurityEvent
from app.models.auth_rate_limit import (
    RATE_LIMIT_SCOPE_IDENTIFIER,
    RATE_LIMIT_SCOPE_IP,
)
from app.models.security_event import (
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_USER_REQUESTED,
)
from app.services.auth_rate_limit import (
    RateLimitKeyError,
    RateLimitStoreError,
    active_cooldown,
    delete_expired_buckets,
    get_bucket,
    identifier_bucket_key,
    ip_bucket_key,
    policy_for_scope,
    record_failure,
    reset_identifier_bucket,
)

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
IDENTIFIER = "rate-limit-test@example.com"


def _security_event_count() -> int:
    return db.session.scalar(select(func.count(SecurityEvent.id))) or 0


def test_first_failure_and_atomic_increment(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)

    first = record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)
    second = record_failure(
        RATE_LIMIT_SCOPE_IDENTIFIER,
        key,
        now=NOW + timedelta(seconds=1),
    )

    assert first.failure_count == 1
    assert first.window_start == NOW
    assert first.blocked_until is None
    assert second.failure_count == 2
    assert second.window_start == NOW
    assert second.blocked_until is None


def test_identifier_cooldown_tiers_are_configured(app: Flask) -> None:
    policy = policy_for_scope(RATE_LIMIT_SCOPE_IDENTIFIER)

    assert policy.cooldown_for(4) == 0
    assert policy.cooldown_for(5) == 60
    assert policy.cooldown_for(10) == 300
    assert policy.cooldown_for(20) == 900


def test_identifier_can_reach_third_cooldown_tier(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "AUTH_RATE_LIMIT_WINDOW_SECONDS", 100_000)
    key = identifier_bucket_key(IDENTIFIER)
    now = NOW
    cooldowns: list[int] = []

    for _ in range(20):
        state = record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=now)
        if state.just_blocked:
            cooldowns.append(state.retry_after_seconds(now))
        if state.blocked_until is not None:
            now = state.blocked_until + timedelta(seconds=1)
        else:
            now += timedelta(seconds=1)

    assert cooldowns == [60] * 5 + [300] * 10 + [900]


def test_fixed_window_expiry_resets_counter(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)
    for offset in range(3):
        record_failure(
            RATE_LIMIT_SCOPE_IDENTIFIER,
            key,
            now=NOW + timedelta(seconds=offset),
        )

    reset = record_failure(
        RATE_LIMIT_SCOPE_IDENTIFIER,
        key,
        now=NOW + timedelta(seconds=901),
    )

    assert reset.failure_count == 1
    assert reset.window_start == NOW + timedelta(seconds=901)
    assert reset.blocked_until is None


def test_progressive_cooldown_and_no_extension_while_blocked(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)
    for _ in range(5):
        state = record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)

    assert state.failure_count == 5
    assert state.blocked_until == NOW + timedelta(seconds=60)
    assert state.is_blocked(NOW + timedelta(seconds=30))
    assert not state.is_blocked(NOW + timedelta(seconds=61))
    assert active_cooldown(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW + timedelta(seconds=30))

    while_blocked = record_failure(
        RATE_LIMIT_SCOPE_IDENTIFIER,
        key,
        now=NOW + timedelta(seconds=30),
    )
    assert while_blocked.failure_count == 6
    assert while_blocked.blocked_until == NOW + timedelta(seconds=60)

    # Reach the 10-failure tier after each 60-second cooldown expires.
    current = NOW + timedelta(seconds=61)
    for expected_count in range(7, 11):
        state = record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=current)
        assert state.failure_count == expected_count
        current += timedelta(seconds=61)

    assert state.failure_count == 10
    assert state.blocked_until == current - timedelta(seconds=61) + timedelta(seconds=300)


def test_reset_identifier_bucket(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)
    for _ in range(5):
        record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)

    assert reset_identifier_bucket(IDENTIFIER) == 1
    assert get_bucket(RATE_LIMIT_SCOPE_IDENTIFIER, key) is None

    fresh = record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)
    assert fresh.failure_count == 1
    assert fresh.blocked_until is None


def test_cleanup_is_bounded_idempotent_and_does_not_touch_security_events(app: Flask) -> None:
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
    before_events = _security_event_count()

    cutoff = NOW - timedelta(hours=48)
    rows = [
        AuthRateLimit(
            scope=RATE_LIMIT_SCOPE_IDENTIFIER,
            key_hash=f"{index:064x}",
            window_start=updated_at - timedelta(minutes=1),
            failure_count=1,
            blocked_until=None,
            updated_at=updated_at,
        )
        for index, updated_at in enumerate(
            (
                cutoff - timedelta(seconds=3),
                cutoff - timedelta(seconds=2),
                cutoff - timedelta(seconds=1),
                cutoff,
                cutoff + timedelta(seconds=1),
            ),
            start=1,
        )
    ]
    db.session.add_all(rows)
    db.session.commit()

    assert delete_expired_buckets(batch_size=2, now=NOW) == 2
    assert delete_expired_buckets(batch_size=2, now=NOW) == 1
    assert delete_expired_buckets(batch_size=2, now=NOW) == 0
    assert delete_expired_buckets(batch_size=2, now=NOW) == 0

    remaining = set(db.session.scalars(select(AuthRateLimit.key_hash)).all())
    assert remaining == {f"{4:064x}", f"{5:064x}"}
    assert _security_event_count() == before_events


def test_cleanup_batch_size_is_bounded(app: Flask) -> None:
    with pytest.raises(ValueError):
        delete_expired_buckets(batch_size=0, now=NOW)
    with pytest.raises(ValueError):
        delete_expired_buckets(batch_size=5001, now=NOW)


def test_concurrent_increments_are_atomic(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)

    def increment() -> None:
        with app.app_context():
            record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)

    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(lambda _index: increment(), range(10)))

    with app.app_context():
        state = get_bucket(RATE_LIMIT_SCOPE_IDENTIFIER, key)
    assert state is not None
    assert state.failure_count == 10


def test_multiple_app_instances_share_postgres_state(app: Flask) -> None:
    key = identifier_bucket_key(IDENTIFIER)
    second_app = create_app(
        "testing",
        {
            "SECURITY_EVENT_HASH_KEY": app.config["SECURITY_EVENT_HASH_KEY"],
            "SQLALCHEMY_DATABASE_URI": app.config["SQLALCHEMY_DATABASE_URI"],
        },
    )

    record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)
    with second_app.app_context():
        record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW + timedelta(seconds=1))

    state = get_bucket(RATE_LIMIT_SCOPE_IDENTIFIER, key)
    assert state is not None
    assert state.failure_count == 2


class _FailingSession:
    """Session stand-in whose entry fails before any SQL runs."""

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self) -> _FailingSession:
        raise SQLAlchemyError("simulated rate-limit store failure")

    def __exit__(self, *_exc) -> bool:
        return False


def test_store_failure_is_typed_and_does_not_create_a_row(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = identifier_bucket_key(IDENTIFIER)
    monkeypatch.setattr("app.services.auth_rate_limit.Session", _FailingSession)

    with pytest.raises(RateLimitStoreError):
        record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)

    count = db.session.scalar(select(func.count(AuthRateLimit.key_hash))) or 0
    assert count == 0


def test_constrained_pool_releases_all_connections(
    constrained_pool_app: Flask,
) -> None:
    with constrained_pool_app.app_context():
        key = identifier_bucket_key(IDENTIFIER)
        record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, key, now=NOW)
        assert get_bucket(RATE_LIMIT_SCOPE_IDENTIFIER, key) is not None
        assert delete_expired_buckets(batch_size=10, now=NOW + timedelta(days=3)) == 1
        assert db.engine.pool.checkedout() == 0


def test_invalid_scope_and_key_are_rejected(app: Flask) -> None:
    with pytest.raises(RateLimitKeyError):
        record_failure("unknown", "a" * 64, now=NOW)
    with pytest.raises(RateLimitKeyError):
        get_bucket(RATE_LIMIT_SCOPE_IP, "not-a-hash")


def test_store_contains_only_hmac_digests(app: Flask) -> None:
    identifier_key = identifier_bucket_key(IDENTIFIER)
    ip_key = ip_bucket_key("203.0.113.9")
    record_failure(RATE_LIMIT_SCOPE_IDENTIFIER, identifier_key, now=NOW)
    record_failure(RATE_LIMIT_SCOPE_IP, ip_key, now=NOW)

    rows = list(db.session.scalars(select(AuthRateLimit)).all())
    serialized = " ".join(
        " ".join(
            (
                row.scope,
                row.key_hash,
                str(row.window_start),
                str(row.failure_count),
                str(row.blocked_until),
                str(row.updated_at),
            )
        )
        for row in rows
    )

    assert len(rows) == 2
    assert all(len(row.key_hash) == 64 for row in rows)
    assert IDENTIFIER not in serialized
    assert "203.0.113.9" not in serialized


def test_cleanup_cli_deletes_one_bounded_batch(app: Flask) -> None:
    old_updated_at = NOW - timedelta(hours=49)
    db.session.add(
        AuthRateLimit(
            scope=RATE_LIMIT_SCOPE_IDENTIFIER,
            key_hash="a" * 64,
            window_start=old_updated_at - timedelta(minutes=1),
            failure_count=1,
            blocked_until=None,
            updated_at=old_updated_at,
        )
    )
    db.session.commit()

    result = app.test_cli_runner().invoke(args=["auth-rate-limit", "cleanup", "--batch-size", "10"])

    assert result.exit_code == 0
    assert "Deleted 1 expired authentication rate-limit bucket(s)." in result.output
    count = db.session.scalar(select(func.count(AuthRateLimit.key_hash))) or 0
    assert count == 0
