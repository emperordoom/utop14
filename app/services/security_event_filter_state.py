"""Server-side storage for admin security-event filter state.

Security properties:

* the raw token never leaves the browser/process; only its SHA-256 digest is
  persisted;
* the token is 256 bits from ``secrets.token_urlsafe(32)``;
* lookups require the token digest *and* the authenticated admin user id, so
  one admin can never read another admin's state;
* expired states are rejected even before the cleanup job runs;
* neither the token nor the filter payload is ever logged or included in an
  error message.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Final

from flask import Response, current_app
from sqlalchemy import delete, select, update
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from app.models.admin_security_event_filter_state import (
    AdminSecurityEventFilterState,
)
from app.services.security_event_admin import AdminSecurityEventFilters

FILTER_STATE_COOKIE: Final = "utop14_se_filter_state"
FILTER_STATE_COOKIE_PATH: Final = "/admin/security-events"

_TOKEN_BYTES: Final = 32
_TOKEN_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_PAYLOAD_BYTES: Final = 4096
_MIN_TTL_MINUTES: Final = 1
_MAX_TTL_MINUTES: Final = 240
_DEFAULT_TTL_MINUTES: Final = 30
_MAX_CLEANUP_BATCH: Final = 10_000

_ALLOWED_PAYLOAD_KEYS: Final = frozenset(
    {
        "event_type",
        "outcome",
        "reason",
        "date_from",
        "date_to",
        "request_id",
        "identifier_hash",
        "actor_user_id",
        "subject_user_id",
    }
)


class FilterStateError(Exception):
    """Base error for filter-state storage."""


class FilterStateUnavailable(FilterStateError):
    """Raised when the state store cannot be used safely."""


def _now(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware datetime is required.")
    return value.astimezone(UTC)


def filter_state_ttl_minutes() -> int:
    """Return the validated filter-state TTL in minutes."""
    raw = current_app.config.get(
        "ADMIN_SECURITY_EVENT_FILTER_TTL_MINUTES",
        _DEFAULT_TTL_MINUTES,
    )
    if type(raw) is not int or not _MIN_TTL_MINUTES <= raw <= _MAX_TTL_MINUTES:
        raise FilterStateUnavailable("The filter-state TTL is invalid.")
    return raw


def generate_token() -> str:
    """Return a 256-bit URL-safe random token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


def is_valid_token(value: object) -> bool:
    """Return whether ``value`` has the expected opaque-token shape."""
    return isinstance(value, str) and _TOKEN_PATTERN.fullmatch(value) is not None


def token_digest(token: str) -> str:
    """Return the SHA-256 hex digest stored for one raw token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def serialize_filters(filters: AdminSecurityEventFilters) -> dict[str, str]:
    """Return a validated, allowlisted payload for storage."""
    if not isinstance(filters, AdminSecurityEventFilters) or not filters.is_valid:
        raise FilterStateError("Only validated filters can be stored.")
    payload = filters.as_query_params()
    if set(payload) - _ALLOWED_PAYLOAD_KEYS:
        raise FilterStateError("The filter payload contains unsupported fields.")
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > _MAX_PAYLOAD_BYTES:
        raise FilterStateError("The filter payload is too large.")
    return payload


def deserialize_filters(payload: object) -> AdminSecurityEventFilters | None:
    """Rebuild filters from a stored payload, or return ``None`` if invalid."""
    if not isinstance(payload, dict):
        return None
    if set(payload) - _ALLOWED_PAYLOAD_KEYS:
        return None
    values: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(value, str):
            return None
        values[key] = value
    filters = AdminSecurityEventFilters.from_values(**values)
    return filters if filters.is_valid else None


def create_filter_state(
    admin_user_id: int,
    filters: AdminSecurityEventFilters,
    *,
    now: datetime | None = None,
) -> str:
    """Store one state and return the raw token for the cookie."""
    if type(admin_user_id) is not int or admin_user_id <= 0:
        raise FilterStateError("A valid admin user is required.")
    payload = serialize_filters(filters)
    reference = _now(now)
    token = generate_token()
    state = AdminSecurityEventFilterState(
        token_hash=token_digest(token),
        admin_user_id=admin_user_id,
        filters=payload,
        created_at=reference,
        expires_at=reference + timedelta(minutes=filter_state_ttl_minutes()),
        last_accessed_at=reference,
    )
    try:
        db.session.add(state)
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise FilterStateUnavailable("Unable to store filter state.") from exc
    return token


def load_filter_state(
    token: object,
    admin_user_id: int,
    *,
    now: datetime | None = None,
) -> AdminSecurityEventFilters | None:
    """Return the caller's unexpired filters, or ``None`` for any miss.

    Invalid, expired, foreign-owner, and malformed states are indistinguishable
    from a missing state so the response never reveals another admin's data.
    """
    if not is_valid_token(token) or type(admin_user_id) is not int or admin_user_id <= 0:
        return None
    reference = _now(now)
    digest = token_digest(token)  # type: ignore[arg-type]
    try:
        state = db.session.scalar(
            select(AdminSecurityEventFilterState).where(
                AdminSecurityEventFilterState.token_hash == digest,
                AdminSecurityEventFilterState.admin_user_id == admin_user_id,
                AdminSecurityEventFilterState.expires_at > reference,
            )
        )
        if state is None:
            return None
        filters = deserialize_filters(state.filters)
        if filters is None:
            return None
        db.session.execute(
            update(AdminSecurityEventFilterState)
            .where(AdminSecurityEventFilterState.token_hash == digest)
            .values(last_accessed_at=reference)
        )
        db.session.commit()
        return filters
    except SQLAlchemyError:
        db.session.rollback()
        return None


def delete_filter_state(token: object, admin_user_id: int) -> None:
    """Delete one state owned by the caller.  Missing state is a no-op."""
    if not is_valid_token(token) or type(admin_user_id) is not int or admin_user_id <= 0:
        return
    try:
        db.session.execute(
            delete(AdminSecurityEventFilterState).where(
                AdminSecurityEventFilterState.token_hash == token_digest(token),  # type: ignore[arg-type]
                AdminSecurityEventFilterState.admin_user_id == admin_user_id,
            )
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()


def delete_filter_states_for_admin(admin_user_id: int) -> None:
    """Delete every filter state owned by one admin (used on logout)."""
    if type(admin_user_id) is not int or admin_user_id <= 0:
        return
    try:
        db.session.execute(
            delete(AdminSecurityEventFilterState).where(
                AdminSecurityEventFilterState.admin_user_id == admin_user_id
            )
        )
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()


def set_filter_state_cookie(response: Response, token: str) -> None:
    """Attach the opaque token to the response as an HttpOnly cookie."""
    response.set_cookie(
        FILTER_STATE_COOKIE,
        token,
        max_age=filter_state_ttl_minutes() * 60,
        httponly=True,
        secure=bool(current_app.config.get("SESSION_COOKIE_SECURE", False)),
        samesite="Lax",
        path=FILTER_STATE_COOKIE_PATH,
    )


def clear_filter_state_cookie(response: Response) -> None:
    """Remove the filter-state cookie from the browser."""
    response.delete_cookie(FILTER_STATE_COOKIE, path=FILTER_STATE_COOKIE_PATH)


def cleanup_expired_filter_states(
    *,
    limit: int = 1000,
    now: datetime | None = None,
) -> int:
    """Delete at most ``limit`` expired states and return the deleted count."""
    if type(limit) is not int or not 1 <= limit <= _MAX_CLEANUP_BATCH:
        raise FilterStateError("The cleanup batch limit is invalid.")
    reference = _now(now)
    try:
        expired = (
            select(AdminSecurityEventFilterState.token_hash)
            .where(AdminSecurityEventFilterState.expires_at <= reference)
            .limit(limit)
        )
        result = db.session.execute(
            delete(AdminSecurityEventFilterState).where(
                AdminSecurityEventFilterState.token_hash.in_(expired)
            )
        )
        db.session.commit()
        return int(result.rowcount or 0)
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise FilterStateUnavailable("Unable to clean up filter state.") from exc
