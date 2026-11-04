"""Administrative audit logging, context and read services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Final

from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from app.extensions import db
from app.models import AuditLog, User
from app.models.audit_log import (
    AUDIT_ACTIONS,
    AUDIT_MAX_EMAIL_LENGTH,
    AUDIT_MAX_REQUEST_ID_LENGTH,
    AUDIT_MAX_USER_AGENT_LENGTH,
)
from app.request_context import (
    current_request_id,
    current_request_ip,
    current_user_agent,
    normalize_ip_address,
    normalize_request_id,
    sanitize_user_agent,
)

_MAX_FILTER_LENGTH: Final = 80
_PER_PAGE: Final = 20
_FORBIDDEN_SNAPSHOT_KEY_FRAGMENTS: Final = (
    "password",
    "hash",
    "token",
    "secret",
    "session",
    "csrf",
    "credential",
)


class AuditError(Exception):
    """Base error for audit operations."""


class AuditValidationError(AuditError):
    """Raised when audit context, snapshots or filters are invalid."""


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Trusted request metadata attached to one audit event."""

    actor_id: int
    actor_email: str
    ip_address: str
    user_agent: str
    request_id: str | None

    def __post_init__(self) -> None:
        if type(self.actor_id) is not int or self.actor_id <= 0:
            raise AuditValidationError("A valid actor is required.")
        email = self.actor_email.strip().lower() if isinstance(self.actor_email, str) else ""
        if not email or len(email) > AUDIT_MAX_EMAIL_LENGTH:
            raise AuditValidationError("A valid actor email is required.")
        object.__setattr__(self, "actor_email", email)
        object.__setattr__(self, "ip_address", normalize_ip_address(self.ip_address))
        object.__setattr__(self, "user_agent", sanitize_user_agent(self.user_agent))
        object.__setattr__(
            self,
            "request_id",
            normalize_request_id(self.request_id) if self.request_id else None,
        )


@dataclass(frozen=True, slots=True)
class AdminAuditFilters:
    """Normalized admin audit-list filters."""

    action: str | None = None
    actor: str | None = None
    target: str | None = None
    date_from: date | None = None
    date_to: date | None = None
    query: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        action: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        q: str | None = None,
    ) -> AdminAuditFilters:
        """Build filters from untrusted query-string values."""
        normalized_action = action.strip() if isinstance(action, str) else None
        if normalized_action not in AUDIT_ACTIONS:
            normalized_action = None

        return cls(
            action=normalized_action,
            actor=_clean_filter(actor),
            target=_clean_filter(target),
            date_from=_parse_date(date_from),
            date_to=_parse_date(date_to),
            query=_clean_filter(q),
        )

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "q": self.query,
        }
        return {key: value for key, value in values.items() if value}


def _clean_filter(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:_MAX_FILTER_LENGTH]
    return cleaned or None


def _parse_date(value: str | None) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_audit_context(*, actor_id: int, actor_email: str) -> AuditContext:
    """Build trusted request metadata for one admin mutation."""
    return AuditContext(
        actor_id=actor_id,
        actor_email=actor_email,
        ip_address=current_request_ip(),
        user_agent=current_user_agent(),
        request_id=current_request_id(),
    )


def snapshot_profile(user: User) -> dict[str, Any]:
    """Return the allowlisted profile-update snapshot."""
    return {"full_name": user.full_name, "email": user.email}


def snapshot_role(user: User) -> dict[str, Any]:
    """Return the allowlisted role snapshot."""
    return {"role": user.role}


def snapshot_active(user: User) -> dict[str, Any]:
    """Return the allowlisted activation snapshot."""
    return {"is_active": bool(user.is_active)}


def sanitize_snapshot(value: object) -> dict[str, Any]:
    """Validate a flat JSON snapshot and reject sensitive or nested values."""
    if not isinstance(value, dict) or not value:
        raise AuditValidationError("Audit snapshots must be non-empty objects.")

    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise AuditValidationError("Audit snapshot keys must be non-empty strings.")
        lowered = key.lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_SNAPSHOT_KEY_FRAGMENTS):
            raise AuditValidationError("Audit snapshots must not contain sensitive fields.")
        if item is not None and not isinstance(item, (str, int, bool)):
            raise AuditValidationError("Audit snapshot values must be JSON primitives.")
        cleaned[key] = item
    return cleaned


def record_audit_event(
    session: Session,
    *,
    context: AuditContext,
    target: User,
    action: str,
    before_data: object,
    after_data: object,
) -> AuditLog:
    """Add one audit row to the caller's transaction; never commits.

    The caller must commit the same session together with the User mutation.
    """
    if action not in AUDIT_ACTIONS:
        raise AuditValidationError("Unknown audit action.")
    if target.id is None:
        raise AuditValidationError("A persisted target is required.")

    before = sanitize_snapshot(before_data)
    after = sanitize_snapshot(after_data)
    target_email = str(target.email or "").strip().lower()
    if not target_email or len(target_email) > AUDIT_MAX_EMAIL_LENGTH:
        raise AuditValidationError("A valid target email is required.")

    audit = AuditLog(
        actor_id=context.actor_id,
        actor_email=context.actor_email,
        target_user_id=target.id,
        target_email=target_email,
        action=action,
        before_data=before,
        after_data=after,
        ip_address=context.ip_address,
        user_agent=context.user_agent[:AUDIT_MAX_USER_AGENT_LENGTH],
        request_id=(
            context.request_id[:AUDIT_MAX_REQUEST_ID_LENGTH] if context.request_id else None
        ),
    )
    session.add(audit)
    try:
        # The caller flushes the User mutation first.  Flushing only the audit
        # row here lets the service distinguish an audit failure from a User
        # uniqueness failure, while keeping both in one transaction.
        session.flush()
    except SQLAlchemyError as exc:
        raise AuditError("Audit event could not be recorded.") from exc
    return audit


def list_audit_logs(
    filters: AdminAuditFilters,
    *,
    page: int = 1,
    per_page: int = _PER_PAGE,
):
    """Return a paginated, filtered, newest-first audit list."""
    actor_user = aliased(User)
    target_user = aliased(User)
    conditions = []

    if filters.action is not None:
        conditions.append(AuditLog.action == filters.action)
    if filters.actor is not None:
        pattern = f"%{_escape_like(filters.actor)}%"
        conditions.append(
            or_(
                AuditLog.actor_email.ilike(pattern, escape="\\"),
                actor_user.full_name.ilike(pattern, escape="\\"),
            )
        )
    if filters.target is not None:
        pattern = f"%{_escape_like(filters.target)}%"
        conditions.append(
            or_(
                AuditLog.target_email.ilike(pattern, escape="\\"),
                target_user.full_name.ilike(pattern, escape="\\"),
            )
        )
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                AuditLog.actor_email.ilike(pattern, escape="\\"),
                AuditLog.target_email.ilike(pattern, escape="\\"),
                actor_user.full_name.ilike(pattern, escape="\\"),
                target_user.full_name.ilike(pattern, escape="\\"),
            )
        )
    if filters.date_from is not None:
        conditions.append(
            AuditLog.created_at >= datetime.combine(filters.date_from, time.min, tzinfo=UTC)
        )
    if filters.date_to is not None:
        conditions.append(
            AuditLog.created_at
            < datetime.combine(
                filters.date_to + timedelta(days=1),
                time.min,
                tzinfo=UTC,
            )
        )

    statement = (
        select(AuditLog)
        .outerjoin(actor_user, AuditLog.actor_id == actor_user.id)
        .outerjoin(target_user, AuditLog.target_user_id == target_user.id)
        .where(*conditions)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=max(1, per_page),
        error_out=False,
    )


def get_audit_log(log_id: int) -> AuditLog | None:
    """Return one audit record by primary key."""
    return db.session.get(AuditLog, log_id)
