"""Read-only administrative security-event list and filter service."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Final

from sqlalchemy import false, select
from sqlalchemy.orm import load_only

from app.extensions import db
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_EVENT_TYPES,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_OUTCOMES,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
    SECURITY_REASONS,
    SecurityEvent,
)
from app.request_context import normalize_request_id

PER_PAGE: Final = 20
MAX_PAGE: Final = 1000

_MAX_FILTER_LENGTH: Final = 80
_MAX_REQUEST_ID_LENGTH: Final = 64
_MAX_HASH_LENGTH: Final = 64
_MAX_USER_ID_LENGTH: Final = 10
# ``User.id`` is a PostgreSQL INTEGER primary key.
_MAX_USER_ID: Final = 2_147_483_647

EVENT_TYPE_CHOICES: Final = (
    (SECURITY_EVENT_LOGIN_SUCCEEDED, "Login succeeded"),
    (SECURITY_EVENT_LOGIN_FAILED, "Login failed"),
    (SECURITY_EVENT_LOGOUT, "Logout"),
)
OUTCOME_CHOICES: Final = (
    (SECURITY_OUTCOME_SUCCESS, "Success"),
    (SECURITY_OUTCOME_FAILURE, "Failure"),
)
REASON_GROUPS: Final = (
    ("Login succeeded", ((SECURITY_REASON_AUTHENTICATED, "Authenticated"),)),
    (
        "Login failed",
        (
            (SECURITY_REASON_UNKNOWN_ACCOUNT, "Unknown account"),
            (SECURITY_REASON_INACTIVE_ACCOUNT, "Inactive account"),
            (SECURITY_REASON_INVALID_PASSWORD, "Invalid password"),
        ),
    ),
    ("Logout", ((SECURITY_REASON_USER_REQUESTED, "User requested"),)),
)

_REASON_EVENT_TYPES: Final = {
    SECURITY_REASON_AUTHENTICATED: SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_REASON_UNKNOWN_ACCOUNT: SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_REASON_INACTIVE_ACCOUNT: SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_REASON_INVALID_PASSWORD: SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_REASON_USER_REQUESTED: SECURITY_EVENT_LOGOUT,
}

_LIST_COLUMNS = (
    SecurityEvent.id,
    SecurityEvent.created_at,
    SecurityEvent.event_type,
    SecurityEvent.outcome,
    SecurityEvent.reason_code,
    SecurityEvent.actor_user_id,
    SecurityEvent.actor_email,
    SecurityEvent.subject_user_id,
    SecurityEvent.subject_email,
    SecurityEvent.ip_address,
    SecurityEvent.request_id,
)


def _clean_value(
    values: str | Sequence[str] | None,
    *,
    label: str,
    max_length: int,
) -> tuple[str | None, str | None]:
    """Return one stripped filter value, or an error for ambiguity/overflow."""
    if values is None:
        return None, None
    if isinstance(values, str):
        raw_values: list[object] = [values]
    else:
        try:
            raw_values = list(values)
        except TypeError:
            return None, f"{label} is invalid."
    if any(not isinstance(value, str) for value in raw_values):
        return None, f"{label} is invalid."

    non_empty = [value.strip() for value in raw_values if value.strip()]
    if len(non_empty) > 1:
        return None, f"{label} may be provided only once."
    if not non_empty:
        return None, None
    value = non_empty[0]
    if len(value) > max_length:
        return None, f"{label} is too long."
    return value, None


def _parse_date(
    values: str | Sequence[str] | None,
    *,
    label: str,
) -> tuple[date | None, str | None]:
    value, error = _clean_value(values, label=label, max_length=10)
    if error is not None or value is None:
        return None, error
    try:
        return date.fromisoformat(value), None
    except ValueError:
        return None, f"{label} must be a valid ISO date."


def _parse_user_id(
    values: str | Sequence[str] | None,
    *,
    label: str,
) -> tuple[int | None, str | None]:
    value, error = _clean_value(
        values,
        label=label,
        max_length=_MAX_USER_ID_LENGTH,
    )
    if error is not None or value is None:
        return None, error
    if not (value.isascii() and value.isdigit()):
        return None, f"{label} must be a positive integer within the allowed range."
    user_id = int(value)
    if user_id <= 0 or user_id > _MAX_USER_ID:
        return None, f"{label} must be a positive integer within the allowed range."
    return user_id, None


@dataclass(frozen=True, slots=True)
class AdminSecurityEventFilters:
    """Normalized and self-validating admin security-event filters."""

    event_type: str | None = None
    outcome: str | None = None
    reason_code: str | None = None
    date_from: date | None = None
    date_to: date | None = None
    request_id: str | None = None
    identifier_hash: str | None = None
    actor_user_id: int | None = None
    subject_user_id: int | None = None
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        errors = list(self.errors)

        event_type = self.event_type
        if isinstance(event_type, str):
            event_type = event_type.strip() or None
        if event_type is not None and (
            not isinstance(event_type, str) or event_type not in SECURITY_EVENT_TYPES
        ):
            errors.append("Select a valid event type.")
            event_type = None
        object.__setattr__(self, "event_type", event_type)

        outcome = self.outcome
        if isinstance(outcome, str):
            outcome = outcome.strip() or None
        if outcome is not None and (
            not isinstance(outcome, str) or outcome not in SECURITY_OUTCOMES
        ):
            errors.append("Select a valid outcome.")
            outcome = None
        object.__setattr__(self, "outcome", outcome)

        reason_code = self.reason_code
        if isinstance(reason_code, str):
            reason_code = reason_code.strip() or None
        if reason_code is not None:
            if not isinstance(reason_code, str) or reason_code not in SECURITY_REASONS:
                errors.append("Select a valid reason.")
                reason_code = None
            else:
                compatible_event_type = _REASON_EVENT_TYPES[reason_code]
                if event_type is None:
                    event_type = compatible_event_type
                    object.__setattr__(self, "event_type", event_type)
                elif event_type != compatible_event_type:
                    errors.append("Reason is not compatible with the selected event type.")
        object.__setattr__(self, "reason_code", reason_code)

        if self.date_from is not None and type(self.date_from) is not date:
            errors.append("From date must be a valid ISO date.")
            object.__setattr__(self, "date_from", None)
        if self.date_to is not None and type(self.date_to) is not date:
            errors.append("To date must be a valid ISO date.")
            object.__setattr__(self, "date_to", None)
        if (
            self.date_from is not None
            and self.date_to is not None
            and self.date_from > self.date_to
        ):
            errors.append("From date must be on or before to date.")

        request_id = self.request_id
        if isinstance(request_id, str):
            request_id = request_id.strip() or None
        if request_id is not None:
            if not isinstance(request_id, str):
                errors.append("Request ID must be a valid normalized request ID.")
                request_id = None
            else:
                normalized = normalize_request_id(request_id)
                if normalized is None:
                    errors.append("Request ID must be a valid normalized request ID.")
                    request_id = None
                else:
                    request_id = normalized
        object.__setattr__(self, "request_id", request_id)

        identifier_hash = self.identifier_hash
        if isinstance(identifier_hash, str):
            identifier_hash = identifier_hash.strip() or None
        if identifier_hash is not None and (
            not isinstance(identifier_hash, str)
            or len(identifier_hash) != _MAX_HASH_LENGTH
            or any(character not in "0123456789abcdef" for character in identifier_hash)
        ):
            errors.append("Identifier hash must be exactly 64 lowercase hexadecimal characters.")
            identifier_hash = None
        object.__setattr__(self, "identifier_hash", identifier_hash)

        for field_name, label in (
            ("actor_user_id", "Actor user ID"),
            ("subject_user_id", "Subject user ID"),
        ):
            value = getattr(self, field_name)
            if value is None:
                continue
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > _MAX_USER_ID
            ):
                errors.append(f"{label} must be a positive integer within the allowed range.")
                object.__setattr__(self, field_name, None)

        object.__setattr__(self, "errors", tuple(errors))

    @property
    def is_valid(self) -> bool:
        """Whether every supplied filter passed validation."""
        return not self.errors

    @classmethod
    def from_values(
        cls,
        *,
        event_type: str | Sequence[str] | None = None,
        outcome: str | Sequence[str] | None = None,
        reason: str | Sequence[str] | None = None,
        date_from: str | Sequence[str] | None = None,
        date_to: str | Sequence[str] | None = None,
        request_id: str | Sequence[str] | None = None,
        identifier_hash: str | Sequence[str] | None = None,
        actor_user_id: str | Sequence[str] | None = None,
        subject_user_id: str | Sequence[str] | None = None,
    ) -> AdminSecurityEventFilters:
        """Build filters from untrusted query-string values."""
        errors: list[str] = []

        def clean(
            values: str | Sequence[str] | None,
            label: str,
            max_length: int,
        ) -> str | None:
            value, error = _clean_value(values, label=label, max_length=max_length)
            if error is not None:
                errors.append(error)
            return value

        raw_event_type = clean(event_type, "Event type", _MAX_FILTER_LENGTH)
        raw_outcome = clean(outcome, "Outcome", _MAX_FILTER_LENGTH)
        raw_reason = clean(reason, "Reason", _MAX_FILTER_LENGTH)
        parsed_date_from, error_from = _parse_date(date_from, label="From date")
        if error_from is not None:
            errors.append(error_from)
        parsed_date_to, error_to = _parse_date(date_to, label="To date")
        if error_to is not None:
            errors.append(error_to)
        raw_request_id = clean(request_id, "Request ID", _MAX_REQUEST_ID_LENGTH)
        raw_identifier_hash = clean(
            identifier_hash,
            "Identifier hash",
            _MAX_HASH_LENGTH,
        )
        parsed_actor_id, error_actor = _parse_user_id(actor_user_id, label="Actor user ID")
        if error_actor is not None:
            errors.append(error_actor)
        parsed_subject_id, error_subject = _parse_user_id(
            subject_user_id,
            label="Subject user ID",
        )
        if error_subject is not None:
            errors.append(error_subject)

        return cls(
            event_type=raw_event_type,
            outcome=raw_outcome,
            reason_code=raw_reason,
            date_from=parsed_date_from,
            date_to=parsed_date_to,
            request_id=raw_request_id,
            identifier_hash=raw_identifier_hash,
            actor_user_id=parsed_actor_id,
            subject_user_id=parsed_subject_id,
            errors=tuple(errors),
        )

    def as_query_params(self) -> dict[str, str]:
        """Return active normalized filters for pagination links."""
        values = {
            "event_type": self.event_type,
            "outcome": self.outcome,
            "reason": self.reason_code,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "request_id": self.request_id,
            "identifier_hash": self.identifier_hash,
            "actor_user_id": str(self.actor_user_id) if self.actor_user_id is not None else None,
            "subject_user_id": (
                str(self.subject_user_id) if self.subject_user_id is not None else None
            ),
        }
        return {key: value for key, value in values.items() if value is not None}


def normalize_page(value: object) -> int:
    """Return a safe positive page number bounded by ``MAX_PAGE``."""
    if isinstance(value, bool):
        return 1
    if isinstance(value, int) and value >= 1:
        return min(value, MAX_PAGE)
    return 1


def list_security_events(
    filters: AdminSecurityEventFilters | None = None,
    *,
    page: int = 1,
):
    """Return one newest-first page of security events.

    The list deliberately omits identifier hashes, metadata and User-Agent
    values; those remain detail-view concerns.  The page size is fixed at 20.
    Invalid filter objects fail closed to an always-false predicate.
    """
    if filters is None:
        filters = AdminSecurityEventFilters()

    conditions = []
    if not isinstance(filters, AdminSecurityEventFilters) or not filters.is_valid:
        conditions.append(false())
    else:
        if filters.event_type is not None:
            conditions.append(SecurityEvent.event_type == filters.event_type)
        if filters.outcome is not None:
            conditions.append(SecurityEvent.outcome == filters.outcome)
        if filters.reason_code is not None:
            conditions.append(SecurityEvent.reason_code == filters.reason_code)
        if filters.date_from is not None:
            conditions.append(
                SecurityEvent.created_at
                >= datetime.combine(filters.date_from, time.min, tzinfo=UTC)
            )
        if filters.date_to is not None:
            conditions.append(
                SecurityEvent.created_at <= datetime.combine(filters.date_to, time.max, tzinfo=UTC)
            )
        if filters.request_id is not None:
            conditions.append(SecurityEvent.request_id == filters.request_id)
        if filters.identifier_hash is not None:
            conditions.append(SecurityEvent.identifier_hash == filters.identifier_hash)
        if filters.actor_user_id is not None:
            conditions.append(SecurityEvent.actor_user_id == filters.actor_user_id)
        if filters.subject_user_id is not None:
            conditions.append(SecurityEvent.subject_user_id == filters.subject_user_id)

    statement = (
        select(SecurityEvent)
        .options(load_only(*_LIST_COLUMNS))
        .where(*conditions)
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
    )
    return db.paginate(
        statement,
        page=normalize_page(page),
        per_page=PER_PAGE,
        error_out=False,
    )
