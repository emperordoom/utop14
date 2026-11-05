"""PostgreSQL-backed fixed-window authentication rate-limit foundation.

This module deliberately does not integrate with authentication routes yet.
M14.3.2 will call the key derivation and store APIs from the login flow.
Raw identifiers and IP addresses are never stored: bucket keys are HMAC-SHA256
digests with domain separation.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Final

from flask import current_app
from sqlalchemy import case, delete, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.extensions import db
from app.models.auth_rate_limit import (
    RATE_LIMIT_SCOPE_COMBINED,
    RATE_LIMIT_SCOPE_IDENTIFIER,
    RATE_LIMIT_SCOPE_IP,
    RATE_LIMIT_SCOPES,
    AuthRateLimit,
)
from app.models.user import normalize_email
from app.request_context import UNKNOWN_IP_ADDRESS, normalize_ip_address

_KEY_DOMAIN: Final = "utop14.auth_rate_limit.v1"
_KEY_SEPARATOR: Final = "\x00"
_DEFAULT_CLEANUP_BATCH_SIZE: Final = 1000
_MAX_CLEANUP_BATCH_SIZE: Final = 5000

_MISSING_KEY_WARNING_LOCK: Final = Lock()
_missing_key_warning_emitted = False


class RateLimitError(Exception):
    """Base error for rate-limit foundation operations."""


class RateLimitKeyError(RateLimitError):
    """Raised when an identifier, IP address or scope is not usable."""


class RateLimitKeyUnavailable(RateLimitKeyError):
    """Raised when the dedicated HMAC key is not configured."""


class RateLimitConfigurationError(RateLimitError):
    """Raised when the configured rate-limit policy is internally invalid."""


class RateLimitStoreError(RateLimitError):
    """Raised when PostgreSQL cannot read or update rate-limit state."""


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Resolved policy for one rate-limit scope."""

    scope: str
    window_seconds: int
    thresholds: tuple[int, ...]
    cooldowns: tuple[int, ...]
    max_cooldown_seconds: int

    def cooldown_for(self, failure_count: int) -> int:
        """Return the cooldown for the highest reached threshold."""
        if failure_count < self.thresholds[0]:
            return 0
        cooldown = 0
        for threshold, candidate in zip(self.thresholds, self.cooldowns, strict=True):
            if failure_count >= threshold:
                cooldown = candidate
            else:
                break
        return min(cooldown, self.max_cooldown_seconds)


@dataclass(frozen=True, slots=True)
class BucketState:
    """A detached snapshot of one rate-limit bucket."""

    scope: str
    key_hash: str
    window_start: datetime
    failure_count: int
    blocked_until: datetime | None

    def is_blocked(self, now: datetime | None = None) -> bool:
        """Return whether the bucket is currently in cooldown."""
        reference = _normalize_now(now)
        return self.blocked_until is not None and self.blocked_until > reference

    def retry_after_seconds(self, now: datetime | None = None) -> int:
        """Return rounded-up remaining cooldown seconds, or zero."""
        reference = _normalize_now(now)
        if self.blocked_until is None or self.blocked_until <= reference:
            return 0
        return max(0, math.ceil((self.blocked_until - reference).total_seconds()))


def _warn_missing_hash_key() -> None:
    """Log a missing HMAC key at most once per worker process."""
    global _missing_key_warning_emitted

    if _missing_key_warning_emitted:
        return
    with _MISSING_KEY_WARNING_LOCK:
        if _missing_key_warning_emitted:
            return
        _missing_key_warning_emitted = True

    current_app.logger.error(
        "SECURITY_EVENT_HASH_KEY is not configured; rate-limit keys unavailable."
    )


def _hmac_key() -> bytes:
    key = current_app.config.get("SECURITY_EVENT_HASH_KEY")
    if not isinstance(key, str) or not key:
        _warn_missing_hash_key()
        raise RateLimitKeyUnavailable(
            "Rate-limit HMAC key is not configured; raw identifiers are not used."
        )
    return key.encode("utf-8")


def _hash_parts(scope: str, *parts: str) -> str:
    payload = _KEY_SEPARATOR.join((_KEY_DOMAIN, scope, *parts))
    digest = hmac.new(_hmac_key(), payload.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def _normalize_identifier(identifier: object) -> str:
    if not isinstance(identifier, str):
        raise RateLimitKeyError("A valid login identifier is required.")
    normalized = normalize_email(identifier)
    if not normalized or len(normalized) > 255 or "\x00" in normalized:
        raise RateLimitKeyError("A valid login identifier is required.")
    return normalized


def _normalize_ip(ip_address: object) -> str:
    if not isinstance(ip_address, str):
        raise RateLimitKeyError("A valid client IP address is required.")
    normalized = normalize_ip_address(ip_address)
    if normalized == UNKNOWN_IP_ADDRESS:
        raise RateLimitKeyError("A valid client IP address is required.")
    return normalized


def _validate_scope(scope: str) -> None:
    if scope not in RATE_LIMIT_SCOPES:
        raise RateLimitKeyError("An unknown rate-limit scope was supplied.")


def _validate_key_hash(key_hash: object) -> str:
    if (
        not isinstance(key_hash, str)
        or len(key_hash) != 64
        or any(character not in "0123456789abcdef" for character in key_hash)
    ):
        raise RateLimitKeyError("A valid rate-limit bucket key is required.")
    return key_hash


def identifier_bucket_key(identifier: str) -> str:
    """Return a domain-separated HMAC key for a normalized login identifier."""
    return _hash_parts(
        RATE_LIMIT_SCOPE_IDENTIFIER,
        _normalize_identifier(identifier),
    )


def ip_bucket_key(ip_address: str) -> str:
    """Return a domain-separated HMAC key for a canonical IP address."""
    return _hash_parts(RATE_LIMIT_SCOPE_IP, _normalize_ip(ip_address))


def combined_bucket_key(ip_address: str, identifier: str) -> str:
    """Return a domain-separated HMAC key for one IP/identifier pair."""
    return _hash_parts(
        RATE_LIMIT_SCOPE_COMBINED,
        _normalize_ip(ip_address),
        _normalize_identifier(identifier),
    )


def _normalize_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware datetime is required.")
    return value.astimezone(UTC)


def _to_utc(value: datetime | None) -> datetime | None:
    return value.astimezone(UTC) if value is not None else None


def policy_for_scope(scope: str) -> RateLimitPolicy:
    """Resolve and validate the configured policy for one scope."""
    _validate_scope(scope)
    if scope == RATE_LIMIT_SCOPE_IDENTIFIER:
        max_failures = current_app.config["AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES"]
        thresholds = current_app.config["AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS"]
        cooldowns = current_app.config["AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS"]
        max_cooldown = current_app.config["AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS"]
    elif scope == RATE_LIMIT_SCOPE_IP:
        max_failures = current_app.config["AUTH_RATE_LIMIT_IP_MAX_FAILURES"]
        thresholds = current_app.config["AUTH_RATE_LIMIT_IP_THRESHOLDS"]
        cooldowns = current_app.config["AUTH_RATE_LIMIT_IP_COOLDOWNS"]
        max_cooldown = current_app.config["AUTH_RATE_LIMIT_IP_MAX_COOLDOWN_SECONDS"]
    else:
        max_failures = current_app.config["AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES"]
        thresholds = current_app.config["AUTH_RATE_LIMIT_COMBINED_THRESHOLDS"]
        cooldowns = current_app.config["AUTH_RATE_LIMIT_COMBINED_COOLDOWNS"]
        max_cooldown = current_app.config["AUTH_RATE_LIMIT_COMBINED_MAX_COOLDOWN_SECONDS"]

    if (
        type(max_failures) is not int
        or max_failures <= 0
        or not isinstance(thresholds, tuple)
        or not thresholds
        or not isinstance(cooldowns, tuple)
        or len(cooldowns) != len(thresholds)
        or any(type(value) is not int or value <= 0 for value in thresholds + cooldowns)
        or any(thresholds[index] >= thresholds[index + 1] for index in range(len(thresholds) - 1))
        or thresholds[-1] != max_failures
        or type(max_cooldown) is not int
        or max_cooldown <= 0
        or any(value > max_cooldown for value in cooldowns)
    ):
        raise RateLimitConfigurationError("The configured rate-limit policy is invalid.")

    window_seconds = current_app.config.get("AUTH_RATE_LIMIT_WINDOW_SECONDS")
    if type(window_seconds) is not int or window_seconds <= 0:
        raise RateLimitConfigurationError("The configured rate-limit window is invalid.")

    return RateLimitPolicy(
        scope=scope,
        window_seconds=window_seconds,
        thresholds=thresholds,
        cooldowns=cooldowns,
        max_cooldown_seconds=max_cooldown,
    )


def _bucket_state(row: AuthRateLimit) -> BucketState:
    return BucketState(
        scope=row.scope,
        key_hash=row.key_hash,
        window_start=_to_utc(row.window_start) or row.window_start,
        failure_count=row.failure_count,
        blocked_until=_to_utc(row.blocked_until),
    )


def get_bucket(scope: str, key_hash: str) -> BucketState | None:
    """Return one bucket snapshot without loading ORM objects into callers."""
    _validate_scope(scope)
    key_hash = _validate_key_hash(key_hash)
    try:
        with Session(db.engine) as session:
            row = session.get(AuthRateLimit, (scope, key_hash))
            return _bucket_state(row) if row is not None else None
    except SQLAlchemyError as exc:
        raise RateLimitStoreError("Unable to read rate-limit state.") from exc


def active_cooldown(
    scope: str,
    key_hash: str,
    *,
    now: datetime | None = None,
) -> BucketState | None:
    """Return the bucket when its cooldown is currently active."""
    reference = _normalize_now(now)
    state = get_bucket(scope, key_hash)
    if state is not None and state.is_blocked(reference):
        return state
    return None


def record_failure(
    scope: str,
    key_hash: str,
    *,
    now: datetime | None = None,
) -> BucketState:
    """Atomically increment one failure bucket and apply progressive cooldown."""
    _validate_scope(scope)
    key_hash = _validate_key_hash(key_hash)
    policy = policy_for_scope(scope)
    reference = _normalize_now(now)
    window_cutoff = reference - timedelta(seconds=policy.window_seconds)

    window_expired = AuthRateLimit.window_start <= window_cutoff
    statement = (
        insert(AuthRateLimit)
        .values(
            scope=scope,
            key_hash=key_hash,
            window_start=reference,
            failure_count=1,
            blocked_until=None,
            updated_at=reference,
        )
        .on_conflict_do_update(
            index_elements=[AuthRateLimit.scope, AuthRateLimit.key_hash],
            set_={
                "window_start": case(
                    (window_expired, reference),
                    else_=AuthRateLimit.window_start,
                ),
                "failure_count": case(
                    (window_expired, 1),
                    else_=AuthRateLimit.failure_count + 1,
                ),
                "blocked_until": case(
                    (window_expired, None),
                    else_=AuthRateLimit.blocked_until,
                ),
                "updated_at": reference,
            },
        )
        .returning(
            AuthRateLimit.window_start,
            AuthRateLimit.failure_count,
            AuthRateLimit.blocked_until,
        )
    )

    try:
        with Session(db.engine) as session:
            row = session.execute(statement).one()
            window_start = row.window_start
            failure_count = row.failure_count
            blocked_until = row.blocked_until

            # A request that is already blocked never extends its own cooldown.
            # Once an expired cooldown is encountered, a new failure may enter
            # the next configured tier.
            if blocked_until is None or blocked_until <= reference:
                cooldown = policy.cooldown_for(failure_count)
                if cooldown > 0:
                    blocked_until = reference + timedelta(seconds=cooldown)
                    session.execute(
                        update(AuthRateLimit)
                        .where(
                            AuthRateLimit.scope == scope,
                            AuthRateLimit.key_hash == key_hash,
                        )
                        .values(blocked_until=blocked_until, updated_at=reference)
                    )

            state = BucketState(
                scope=scope,
                key_hash=key_hash,
                window_start=_to_utc(window_start) or window_start,
                failure_count=failure_count,
                blocked_until=_to_utc(blocked_until),
            )
            session.commit()
            return state
    except SQLAlchemyError as exc:
        raise RateLimitStoreError("Unable to update rate-limit state.") from exc


def reset_identifier_bucket(identifier: str) -> int:
    """Reset the identifier failure bucket after a successful login."""
    key_hash = identifier_bucket_key(identifier)
    try:
        with Session(db.engine) as session:
            result = session.execute(
                delete(AuthRateLimit).where(
                    AuthRateLimit.scope == RATE_LIMIT_SCOPE_IDENTIFIER,
                    AuthRateLimit.key_hash == key_hash,
                )
            )
            session.commit()
            return result.rowcount or 0
    except SQLAlchemyError as exc:
        raise RateLimitStoreError("Unable to reset rate-limit state.") from exc


def delete_expired_buckets(
    *,
    batch_size: int = _DEFAULT_CLEANUP_BATCH_SIZE,
    now: datetime | None = None,
) -> int:
    """Delete at most ``batch_size`` stale buckets using a fixed cutoff."""
    if type(batch_size) is not int or not 1 <= batch_size <= _MAX_CLEANUP_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_CLEANUP_BATCH_SIZE}.")
    reference = _normalize_now(now)
    ttl_hours = current_app.config.get("AUTH_RATE_LIMIT_BUCKET_TTL_HOURS")
    if type(ttl_hours) is not int or ttl_hours <= 0:
        raise RateLimitConfigurationError("The configured rate-limit TTL is invalid.")
    cutoff = reference - timedelta(hours=ttl_hours)

    expired_keys = (
        select(AuthRateLimit.scope, AuthRateLimit.key_hash)
        .where(AuthRateLimit.updated_at < cutoff)
        .order_by(
            AuthRateLimit.updated_at,
            AuthRateLimit.scope,
            AuthRateLimit.key_hash,
        )
        .limit(batch_size)
        .subquery()
    )
    statement = delete(AuthRateLimit).where(
        tuple_(AuthRateLimit.scope, AuthRateLimit.key_hash).in_(
            select(expired_keys.c.scope, expired_keys.c.key_hash)
        )
    )

    try:
        with Session(db.engine) as session:
            result = session.execute(statement)
            session.commit()
            return result.rowcount or 0
    except SQLAlchemyError as exc:
        raise RateLimitStoreError("Unable to clean up rate-limit state.") from exc
