"""Login abuse orchestration over the PostgreSQL rate-limit foundation.

The limiter is fail-open for storage/key outages in M14.3.2: authentication must
continue if the rate-limit store is unavailable.  This module never stores or
logs raw identifiers, IP addresses or credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from flask import current_app

from app.request_context import current_request_id, current_request_ip
from app.services.auth_rate_limit import (
    BucketState,
    RateLimitKeyError,
    RateLimitKeyUnavailable,
    RateLimitStoreError,
    active_cooldown,
    combined_bucket_key,
    identifier_bucket_key,
    ip_bucket_key,
    policy_for_scope,
    record_failure,
    reset_identifier_bucket,
)
from app.services.security_events import record_login_throttled

_SCOPE_PRIORITY = {"combined": 3, "identifier": 2, "ip": 1}
_SCOPE_REASON = {
    "ip": "ip_rate_limited",
    "identifier": "identifier_rate_limited",
    "combined": "combined_rate_limited",
}


@dataclass(frozen=True, slots=True)
class LoginThrottleDecision:
    """A currently active throttle decision for one login request."""

    scope: str
    reason_code: str
    retry_after_seconds: int
    window_seconds: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class ThrottleTransition:
    """A newly entered or meaningfully extended block transition."""

    scope: str
    reason_code: str
    retry_after_seconds: int
    window_seconds: int
    failure_count: int


def _enabled() -> bool:
    return current_app.config.get("AUTH_RATE_LIMIT_ENABLED") is True


def _warn_store_failure(exc: RateLimitStoreError, *, scope: str | None = None) -> None:
    current_app.logger.warning(
        "Authentication rate-limit store failure (request_id=%s, scope=%s, %s).",
        current_request_id() or "none",
        scope or "unknown",
        type(exc).__name__,
    )


def _warn_key_failure(exc: RateLimitKeyError) -> None:
    current_app.logger.warning(
        "Authentication rate-limit key unavailable (request_id=%s, %s).",
        current_request_id() or "none",
        type(exc).__name__,
    )


def _bucket_keys(identifier: str) -> tuple[tuple[str, str], ...]:
    """Build available bucket keys; return an empty tuple when unusable."""
    try:
        identifier_key = identifier_bucket_key(identifier)
    except RateLimitKeyUnavailable:
        return ()
    except RateLimitKeyError as exc:
        _warn_key_failure(exc)
        return ()

    keys: list[tuple[str, str]] = [("identifier", identifier_key)]
    try:
        ip_address = current_request_ip()
        ip_key = ip_bucket_key(ip_address)
        combined_key = combined_bucket_key(ip_address, identifier)
    except RateLimitKeyError:
        return tuple(keys)
    keys.extend((("ip", ip_key), ("combined", combined_key)))
    return tuple(keys)


def evaluate_login_throttle(
    identifier: str,
    *,
    now: datetime | None = None,
) -> LoginThrottleDecision | None:
    """Return the most restrictive active throttle, or ``None``."""
    if not _enabled():
        return None
    reference = now or datetime.now(UTC)
    keys = _bucket_keys(identifier)
    if not keys:
        return None

    active: list[tuple[str, BucketState]] = []
    try:
        for scope, key_hash in keys:
            state = active_cooldown(scope, key_hash, now=reference)
            if state is not None:
                active.append((scope, state))
    except RateLimitStoreError as exc:
        _warn_store_failure(exc)
        return None

    if not active:
        return None

    scope, state = max(
        active,
        key=lambda item: (
            item[1].retry_after_seconds(reference),
            _SCOPE_PRIORITY[item[0]],
        ),
    )
    decision = LoginThrottleDecision(
        scope=scope,
        reason_code=_SCOPE_REASON[scope],
        retry_after_seconds=max(1, state.retry_after_seconds(reference)),
        window_seconds=policy_for_scope(scope).window_seconds,
        failure_count=state.failure_count,
    )
    current_app.logger.warning("Login request throttled (scope=%s).", scope)
    return decision


def record_login_failure(
    identifier: str,
    *,
    now: datetime | None = None,
) -> tuple[ThrottleTransition, ...]:
    """Record a failed login across all available scopes.

    Returns only transitions that newly entered a block.  The route emits one
    security event per transition; requests that were already blocked do not
    call this function and therefore do not create repeated events.
    """
    if not _enabled():
        return ()
    reference = now or datetime.now(UTC)
    transitions: list[ThrottleTransition] = []

    for scope, key_hash in _bucket_keys(identifier):
        try:
            state = record_failure(scope, key_hash, now=reference)
        except RateLimitStoreError as exc:
            _warn_store_failure(exc, scope=scope)
            continue
        if not state.just_blocked:
            continue
        transitions.append(
            ThrottleTransition(
                scope=scope,
                reason_code=_SCOPE_REASON[scope],
                retry_after_seconds=max(1, state.retry_after_seconds(reference)),
                window_seconds=policy_for_scope(scope).window_seconds,
                failure_count=state.failure_count,
            )
        )
    return tuple(transitions)


def record_throttle_events(
    identifier: str,
    transitions: tuple[ThrottleTransition, ...],
) -> None:
    """Write best-effort security events for newly entered blocks."""
    for transition in transitions:
        record_login_throttled(
            identifier=identifier,
            reason_code=transition.reason_code,
            scope=transition.scope,
            retry_after_seconds=transition.retry_after_seconds,
            window_seconds=transition.window_seconds,
            failure_count=transition.failure_count,
        )


def reset_login_identifier_bucket(identifier: str) -> int:
    """Best-effort reset of the identifier bucket after successful login."""
    if not _enabled():
        return 0
    try:
        return reset_identifier_bucket(identifier)
    except RateLimitStoreError as exc:
        _warn_store_failure(exc, scope="identifier")
        return 0
    except RateLimitKeyUnavailable:
        return 0
    except RateLimitKeyError as exc:
        _warn_key_failure(exc)
        return 0
