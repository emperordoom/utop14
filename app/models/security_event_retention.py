"""Investigative holds and run log for security-event retention."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

RETENTION_SCOPE_SUCCESS: str = "success_logout"
RETENTION_SCOPE_FAILURE: str = "failure_throttled"
RETENTION_SCOPES: tuple[str, ...] = (
    RETENTION_SCOPE_SUCCESS,
    RETENTION_SCOPE_FAILURE,
)
RETENTION_STATUS_STARTED: str = "started"
RETENTION_STATUS_SUCCESS: str = "success"
# ``partial`` is retained only for historical rows.  New runs report an
# exhausted batch budget through the CLI exit code and metrics instead of a
# synthetic partial run-log row.
RETENTION_STATUS_PARTIAL: str = "partial"
RETENTION_STATUS_FAILED: str = "failed"
RETENTION_STATUSES: tuple[str, ...] = (
    RETENTION_STATUS_STARTED,
    RETENTION_STATUS_SUCCESS,
    RETENTION_STATUS_PARTIAL,
    RETENTION_STATUS_FAILED,
)


class SecurityEventRetentionHold(Base):
    """An investigative hold that prevents one event from being purged.

    At most one row exists per event.  An active row has ``expires_at`` in the
    future; an expired row may be replaced by a new hold through the service.
    The foreign key uses ``ON DELETE CASCADE`` so retention cannot leave an
    orphan hold behind.
    """

    __tablename__ = "security_event_retention_holds"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="security_event_retention_hold_expiry_valid",
        ),
        Index(
            "ix_security_event_retention_holds_expires_at",
            "expires_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    security_event_id: Mapped[int] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class SecurityEventRetentionRun(Base):
    """Append-only operational record for one retention batch or summary."""

    __tablename__ = "security_event_retention_runs"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('success_logout', 'failure_throttled')",
            name="security_event_retention_run_scope_valid",
        ),
        CheckConstraint(
            "status IN ('started', 'success', 'partial', 'failed')",
            name="security_event_retention_run_status_valid",
        ),
        CheckConstraint(
            "deleted_count >= 0",
            name="security_event_retention_run_deleted_nonnegative",
        ),
        CheckConstraint(
            "batch_index >= 0",
            name="security_event_retention_run_batch_nonnegative",
        ),
        UniqueConstraint(
            "run_id",
            "batch_index",
            name="security_event_retention_run_batch_unique",
        ),
        Index(
            "ix_security_event_retention_runs_run_id",
            "run_id",
        ),
        Index(
            "ix_security_event_retention_runs_started_at",
            "started_at",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    batch_index: Mapped[int] = mapped_column(Integer, nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    cutoff: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    deleted_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    # ``session_user`` as observed inside the SECURITY DEFINER function.  This
    # identifies the database credential that executed the batch (for example
    # ``utop14_retention_runner``), not a human or OS job name.
    executed_by: Mapped[str] = mapped_column(String(63), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        server_default=text("now()"),
    )
