"""Append-only administrative audit log model."""

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

AUDIT_ACTION_PROFILE_UPDATED: Final = "user.profile_updated"
AUDIT_ACTION_ROLE_CHANGED: Final = "user.role_changed"
AUDIT_ACTION_ACTIVATED: Final = "user.activated"
AUDIT_ACTION_DEACTIVATED: Final = "user.deactivated"

AUDIT_ACTIONS: Final[tuple[str, ...]] = (
    AUDIT_ACTION_PROFILE_UPDATED,
    AUDIT_ACTION_ROLE_CHANGED,
    AUDIT_ACTION_ACTIVATED,
    AUDIT_ACTION_DEACTIVATED,
)

AUDIT_MAX_USER_AGENT_LENGTH: Final = 512
AUDIT_MAX_REQUEST_ID_LENGTH: Final = 64
AUDIT_MAX_EMAIL_LENGTH: Final = 255


class AuditLog(Base):
    """One immutable administrative user-management event.

    The table is append-only at the application layer and protected by a
    PostgreSQL trigger against row-level UPDATE/DELETE.  The trigger permits
    only the nullable actor/target identity links to be cleared by
    ``ON DELETE SET NULL``; all audit content and snapshots remain immutable.
    A database owner or superuser can still alter or drop the trigger; this is
    not absolute immutability.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint(
            "action IN ("
            "'user.profile_updated', "
            "'user.role_changed', "
            "'user.activated', "
            "'user.deactivated'"
            ")",
            name="audit_log_action_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(before_data) = 'object'",
            name="audit_log_before_object",
        ),
        CheckConstraint(
            "jsonb_typeof(after_data) = 'object'",
            name="audit_log_after_object",
        ),
        CheckConstraint(
            f"char_length(user_agent) <= {AUDIT_MAX_USER_AGENT_LENGTH}",
            name="audit_log_user_agent_length",
        ),
        CheckConstraint(
            f"request_id IS NULL OR char_length(request_id) <= {AUDIT_MAX_REQUEST_ID_LENGTH}",
            name="audit_log_request_id_length",
        ),
        Index("ix_audit_logs_created_at_id", "created_at", "id"),
        Index("ix_audit_logs_action_created_at", "action", "created_at"),
        Index("ix_audit_logs_actor_id_created_at", "actor_id", "created_at"),
        Index(
            "ix_audit_logs_target_user_id_created_at",
            "target_user_id",
            "created_at",
        ),
        Index("ix_audit_logs_request_id", "request_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    actor_email: Mapped[str] = mapped_column(
        String(AUDIT_MAX_EMAIL_LENGTH),
        nullable=False,
    )
    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    target_email: Mapped[str] = mapped_column(
        String(AUDIT_MAX_EMAIL_LENGTH),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    before_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    after_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    user_agent: Mapped[str] = mapped_column(
        String(AUDIT_MAX_USER_AGENT_LENGTH),
        nullable=False,
        default="",
        server_default=text("''"),
    )
    request_id: Mapped[str | None] = mapped_column(
        String(AUDIT_MAX_REQUEST_ID_LENGTH),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    actor: Mapped[User | None] = relationship(foreign_keys=[actor_id])
    target_user: Mapped[User | None] = relationship(foreign_keys=[target_user_id])

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id!r} action={self.action!r}>"
