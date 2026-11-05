"""Best-effort authentication and security event logging.

Security events are stored in the append-only ``security_events`` table.  They
are deliberately independent from the M13 administrative ``audit_logs`` table
because authentication events include unauthenticated subjects and can occur at
much higher volume.

Persistence is best-effort: every public ``record_*`` helper catches failures
internally so an authentication outcome never depends on auditing success.  A
dedicated short-lived SQLAlchemy session is used so a failed event insert cannot
poison the caller's request transaction.

Callers must pass primitive snapshots, not live ORM instances, and must release
the request session's checked-out connection before calling these helpers.  That
keeps the audit insert from requiring a second simultaneous pool connection.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Final

from flask import current_app
from sqlalchemy.orm import Session

from app.extensions import db
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGIN_THROTTLED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_EVENT_TYPES,
    SECURITY_MAX_EMAIL_LENGTH,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_COMBINED_RATE_LIMITED,
    SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
    SECURITY_REASON_IP_RATE_LIMITED,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
    SecurityEvent,
)
from app.models.user import normalize_email
from app.request_context import (
    current_request_id,
    current_request_ip,
    current_user_agent,
    normalize_ip_address,
    normalize_request_id,
    sanitize_user_agent,
)

AUTH_METHOD_PASSWORD: Final = "password"
AUTH_METHOD_REGISTRATION: Final = "registration"
AUTH_METHODS: Final[tuple[str, ...]] = (
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_REGISTRATION,
)

_HASH_DOMAIN_PREFIX: Final = "utop14.security_event.identifier.v1\x00"
_LOGIN_FAILURE_REASONS: Final = (
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
)
_LOGIN_THROTTLE_REASONS: Final = (
    SECURITY_REASON_IP_RATE_LIMITED,
    SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
    SECURITY_REASON_COMBINED_RATE_LIMITED,
)
_RATE_LIMIT_SCOPES: Final = ("ip", "identifier", "combined")

_MISSING_KEY_WARNING_LOCK: Final = Lock()
_missing_key_warning_emitted = False


def _warn_missing_hash_key() -> None:
    """Log the missing-key warning at most once per worker process."""
    global _missing_key_warning_emitted

    if _missing_key_warning_emitted:
        return
    with _MISSING_KEY_WARNING_LOCK:
        if _missing_key_warning_emitted:
            return
        _missing_key_warning_emitted = True

    current_app.logger.error("SECURITY_EVENT_HASH_KEY is not configured; identifier hash omitted.")


# Explicit per-event metadata allowlists.  Values are never taken from request
# payloads beyond the validated names built by the helpers below.
_ALLOWED_METADATA: Final[dict[str, dict[str, type]]] = {
    SECURITY_EVENT_LOGIN_SUCCEEDED: {
        "auth_method": str,
        "remember_requested": bool,
    },
    SECURITY_EVENT_LOGIN_FAILED: {"auth_method": str},
    SECURITY_EVENT_LOGIN_THROTTLED: {
        "scope": str,
        "retry_after_seconds": int,
        "window_seconds": int,
        "failure_count": int,
    },
    SECURITY_EVENT_LOGOUT: {},
}


class SecurityEventValidationError(Exception):
    """Raised internally when an event payload violates the allowlist."""


@dataclass(frozen=True, slots=True)
class SecurityEventContext:
    """Trusted request metadata attached to one security event.

    Unlike the M13 ``AuditContext`` both actor and subject are optional, because
    login failures may not identify an account at all.
    """

    ip_address: str
    user_agent: str
    request_id: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "ip_address", normalize_ip_address(self.ip_address))
        object.__setattr__(self, "user_agent", sanitize_user_agent(self.user_agent))
        object.__setattr__(
            self,
            "request_id",
            normalize_request_id(self.request_id) if self.request_id else None,
        )


def build_security_event_context() -> SecurityEventContext:
    """Build trusted request metadata for one authentication event."""
    return SecurityEventContext(
        ip_address=current_request_ip(),
        user_agent=current_user_agent(),
        request_id=current_request_id(),
    )


def _normalize_email_snapshot(value: object) -> str | None:
    """Return a normalized email snapshot or ``None`` when unusable."""
    if not isinstance(value, str):
        return None
    email = normalize_email(value)
    if not email or len(email) > SECURITY_MAX_EMAIL_LENGTH:
        return None
    return email


def hash_identifier(identifier: object) -> str | None:
    """Return a deterministic HMAC-SHA256 hash for a login identifier.

    ``SECURITY_EVENT_HASH_KEY`` is required in production.  When it is missing
    in another environment the helper returns ``None`` and emits a
    once-per-process configuration warning; it never falls back to
    ``SECRET_KEY`` and never returns the raw identifier.
    """
    if not isinstance(identifier, str):
        return None

    normalized = normalize_email(identifier)
    if not normalized:
        return None

    key = current_app.config.get("SECURITY_EVENT_HASH_KEY")
    if not isinstance(key, str) or not key:
        _warn_missing_hash_key()
        return None

    digest = hmac.new(
        key.encode(),
        f"{_HASH_DOMAIN_PREFIX}{normalized}".encode(),
        hashlib.sha256,
    )
    return digest.hexdigest()


def sanitize_metadata(event_type: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Validate metadata against the event-specific allowlist."""
    if event_type not in SECURITY_EVENT_TYPES:
        raise SecurityEventValidationError("Unknown security event type.")

    allowed = _ALLOWED_METADATA[event_type]
    source = metadata or {}
    cleaned: dict[str, Any] = {}
    for key, expected in allowed.items():
        if key not in source:
            continue
        value = source[key]
        if expected is bool:
            if not isinstance(value, bool):
                raise SecurityEventValidationError("Invalid security event metadata value.")
        elif expected is int:
            if type(value) is not int:
                raise SecurityEventValidationError("Invalid security event metadata value.")
        elif not isinstance(value, expected):
            raise SecurityEventValidationError("Invalid security event metadata value.")
        if key == "auth_method" and value not in AUTH_METHODS:
            raise SecurityEventValidationError("Unknown authentication method.")
        if key == "scope" and value not in _RATE_LIMIT_SCOPES:
            raise SecurityEventValidationError("Unknown rate-limit scope.")
        cleaned[key] = value
    return cleaned


def _persist(event: SecurityEvent) -> None:
    """Insert one event in its own transaction; failures are contained."""
    try:
        with Session(db.engine) as session:
            session.add(event)
            session.commit()
    except Exception as exc:  # noqa: BLE001 - auditing must never break auth
        # Log only safe correlation/type fields.  Exception messages from the
        # database can contain parameter values such as identifiers.
        current_app.logger.error(
            "Security event persistence failed for %s (request_id=%s, %s).",
            event.event_type,
            event.request_id or "none",
            type(exc).__name__,
        )


def _build_event(
    *,
    event_type: str,
    outcome: str,
    reason_code: str,
    context: SecurityEventContext,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    subject_user_id: int | None = None,
    subject_email: str | None = None,
    identifier_hash: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_type=event_type,
        outcome=outcome,
        reason_code=reason_code,
        actor_user_id=actor_user_id,
        actor_email=_normalize_email_snapshot(actor_email),
        subject_user_id=subject_user_id,
        subject_email=_normalize_email_snapshot(subject_email),
        identifier_hash=identifier_hash,
        ip_address=context.ip_address,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata_json=sanitize_metadata(event_type, metadata),
        created_at=datetime.now(UTC),
    )


def record_login_succeeded(
    *,
    user_id: int,
    email: str,
    auth_method: str,
    remember_requested: bool = False,
) -> None:
    """Record one successful authentication from primitive snapshot values."""
    try:
        event = _build_event(
            event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
            outcome=SECURITY_OUTCOME_SUCCESS,
            reason_code=SECURITY_REASON_AUTHENTICATED,
            context=build_security_event_context(),
            actor_user_id=user_id,
            actor_email=email,
            subject_user_id=user_id,
            subject_email=email,
            metadata={
                "auth_method": auth_method,
                "remember_requested": bool(remember_requested),
            },
        )
    except Exception as exc:  # noqa: BLE001 - auditing must never break auth
        current_app.logger.error(
            "Security event build failed for %s (%s).",
            SECURITY_EVENT_LOGIN_SUCCEEDED,
            type(exc).__name__,
        )
        return
    _persist(event)


def record_login_failed(
    *,
    identifier: str,
    reason: str,
    subject_user_id: int | None = None,
    subject_email: str | None = None,
) -> None:
    """Record one failed credential attempt from primitive snapshot values.

    Unknown accounts are represented only by a keyed hash of the normalized
    identifier.  Known but inactive or wrongly-authenticated accounts may carry
    the user id and email snapshot.
    """
    if reason not in _LOGIN_FAILURE_REASONS:
        return

    try:
        event = _build_event(
            event_type=SECURITY_EVENT_LOGIN_FAILED,
            outcome=SECURITY_OUTCOME_FAILURE,
            reason_code=reason,
            context=build_security_event_context(),
            subject_user_id=subject_user_id,
            subject_email=subject_email,
            identifier_hash=hash_identifier(identifier),
            metadata={"auth_method": AUTH_METHOD_PASSWORD},
        )
    except Exception as exc:  # noqa: BLE001 - auditing must never break auth
        current_app.logger.error(
            "Security event build failed for %s (%s).",
            SECURITY_EVENT_LOGIN_FAILED,
            type(exc).__name__,
        )
        return
    _persist(event)


def record_login_throttled(
    *,
    identifier: str,
    reason_code: str,
    scope: str,
    retry_after_seconds: int,
    window_seconds: int,
    failure_count: int,
) -> None:
    """Record one meaningful login throttle transition without raw credentials."""
    if reason_code not in _LOGIN_THROTTLE_REASONS or scope not in _RATE_LIMIT_SCOPES:
        return

    try:
        event = _build_event(
            event_type=SECURITY_EVENT_LOGIN_THROTTLED,
            outcome=SECURITY_OUTCOME_FAILURE,
            reason_code=reason_code,
            context=build_security_event_context(),
            identifier_hash=hash_identifier(identifier),
            metadata={
                "scope": scope,
                "retry_after_seconds": retry_after_seconds,
                "window_seconds": window_seconds,
                "failure_count": failure_count,
            },
        )
    except Exception as exc:  # noqa: BLE001 - auditing must never break auth
        current_app.logger.error(
            "Security event build failed for %s (%s).",
            SECURITY_EVENT_LOGIN_THROTTLED,
            type(exc).__name__,
        )
        return
    _persist(event)


def record_logout(*, user_id: int, email: str) -> None:
    """Record one user-requested logout (best-effort).

    Identity values are captured by the caller before ``logout_user()`` so the
    event is not built from an already-anonymous proxy.
    """
    try:
        event = _build_event(
            event_type=SECURITY_EVENT_LOGOUT,
            outcome=SECURITY_OUTCOME_SUCCESS,
            reason_code=SECURITY_REASON_USER_REQUESTED,
            context=build_security_event_context(),
            actor_user_id=user_id,
            actor_email=email,
            subject_user_id=user_id,
            subject_email=email,
        )
    except Exception as exc:  # noqa: BLE001 - auditing must never break auth
        current_app.logger.error(
            "Security event build failed for %s (%s).",
            SECURITY_EVENT_LOGOUT,
            type(exc).__name__,
        )
        return
    _persist(event)
