"""Server-side admin security-event filter state.

The browser holds only an opaque random token.  This table stores a SHA-256
digest of that token and the validated filter payload, so neither a database
reader nor an access-log reader can recover the raw token or the filters.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AdminSecurityEventFilterState(Base):
    """One expiring filter state owned by one admin user.

    ``token_hash`` is the natural primary key: the state is keyed by the opaque
    token digest, so no surrogate sequence exists and no extra unique index is
    required.  Every lookup must additionally match ``admin_user_id``; the
    database does not enforce row ownership by itself.
    """

    __tablename__ = "admin_security_event_filter_states"
    __table_args__ = (
        CheckConstraint(
            "expires_at > created_at",
            name="admin_security_event_filter_state_expiry_valid",
        ),
        Index(
            "ix_admin_security_event_filter_states_admin_user_id",
            "admin_user_id",
        ),
        Index(
            "ix_admin_security_event_filter_states_expires_at",
            "expires_at",
        ),
    )

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_accessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
