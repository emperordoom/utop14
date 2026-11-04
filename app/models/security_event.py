"""Append-only authentication and security event model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User

SECURITY_EVENT_LOGIN_SUCCEEDED: Final = "auth.login_succeeded"
SECURITY_EVENT_LOGIN_FAILED: Final = "auth.login_failed"
SECURITY_EVENT_LOGOUT: Final = "auth.logout"

SECURITY_EVENT_TYPES: Final[tuple[str, ...]] = (
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGOUT,
)

SECURITY_OUTCOME_SUCCESS: Final = "success"
SECURITY_OUTCOME_FAILURE: Final = "failure"
SECURITY_OUTCOMES: Final[tuple[str, ...]] = (
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_OUTCOME_FAILURE,
)

SECURITY_REASON_AUTHENTICATED: Final = "authenticated"
SECURITY_REASON_UNKNOWN_ACCOUNT: Final = "unknown_account"
SECURITY_REASON_INACTIVE_ACCOUNT: Final = "inactive_account"
SECURITY_REASON_INVALID_PASSWORD: Final = "invalid_password"
SECURITY_REASON_USER_REQUESTED: Final = "user_requested"

SECURITY_REASONS: Final[tuple[str, ...]] = (
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
    SECURITY_REASON_USER_REQUESTED,
)

SECURITY_MAX_USER_AGENT_LENGTH: Final = 512
SECURITY_MAX_REQUEST_ID_LENGTH: Final = 64
SECURITY_MAX_EMAIL_LENGTH: Final = 255


class SecurityEvent(Base):
    """One immutable authentication or security event.

    This table is separate from the M13 administrative ``audit_logs`` table so
    unauthenticated and high-volume authentication events do not change the
    existing audit schema or semantics.  The append-only trigger permits only
    FK ``ON DELETE SET NULL`` clearing of actor/subject identity links.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('auth.login_succeeded', 'auth.login_failed', 'auth.logout')",
            name="security_event_type_valid",
        ),
        CheckConstraint(
            "outcome IN ('success', 'failure')",
            name="security_event_outcome_valid",
        ),
        CheckConstraint(
            "(event_type = 'auth.login_succeeded' "
            "AND outcome = 'success' "
            "AND reason_code = 'authenticated') "
            "OR (event_type = 'auth.login_failed' "
            "AND outcome = 'failure' "
            "AND reason_code IN ('unknown_account', 'inactive_account', 'invalid_password')) "
            "OR (event_type = 'auth.logout' "
            "AND outcome = 'success' "
            "AND reason_code = 'user_requested')",
            name="security_event_reason_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(metadata) = 'object'",
            name="security_event_metadata_object",
        ),
        CheckConstraint(
            f"char_length(user_agent) <= {SECURITY_MAX_USER_AGENT_LENGTH}",
            name="security_event_user_agent_length",
        ),
        CheckConstraint(
            f"request_id IS NULL OR char_length(request_id) <= {SECURITY_MAX_REQUEST_ID_LENGTH}",
            name="security_event_request_id_length",
        ),
        CheckConstraint(
            "identifier_hash IS NULL OR char_length(identifier_hash) = 64",
            name="security_event_identifier_hash_length",
        ),
        Index("ix_security_events_created_at_id", "created_at", "id"),
        Index("ix_security_events_event_type_created_at", "event_type", "created_at"),
        Index("ix_security_events_outcome_created_at", "outcome", "created_at"),
        Index("ix_security_events_actor_user_id_created_at", "actor_user_id", "created_at"),
        Index(
            "ix_security_events_subject_user_id_created_at",
            "subject_user_id",
            "created_at",
        ),
        Index(
            "ix_security_events_identifier_hash_created_at",
            "identifier_hash",
            "created_at",
        ),
        Index("ix_security_events_request_id", "request_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_email: Mapped[str | None] = mapped_column(
        String(SECURITY_MAX_EMAIL_LENGTH),
        nullable=True,
    )
    subject_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    subject_email: Mapped[str | None] = mapped_column(
        String(SECURITY_MAX_EMAIL_LENGTH),
        nullable=True,
    )
    identifier_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    user_agent: Mapped[str] = mapped_column(
        String(SECURITY_MAX_USER_AGENT_LENGTH),
        nullable=False,
        default="",
        server_default=text("''"),
    )
    request_id: Mapped[str | None] = mapped_column(
        String(SECURITY_MAX_REQUEST_ID_LENGTH),
        nullable=True,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    actor: Mapped[User | None] = relationship(foreign_keys=[actor_user_id])
    subject: Mapped[User | None] = relationship(foreign_keys=[subject_user_id])

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id!r} type={self.event_type!r}>"
