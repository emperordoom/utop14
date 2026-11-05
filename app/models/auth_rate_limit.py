"""PostgreSQL-backed authentication rate-limit bucket state."""

from __future__ import annotations

from datetime import datetime
from typing import Final

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

RATE_LIMIT_SCOPE_IP: Final = "ip"
RATE_LIMIT_SCOPE_IDENTIFIER: Final = "identifier"
RATE_LIMIT_SCOPE_COMBINED: Final = "combined"

RATE_LIMIT_SCOPES: Final[tuple[str, ...]] = (
    RATE_LIMIT_SCOPE_IP,
    RATE_LIMIT_SCOPE_IDENTIFIER,
    RATE_LIMIT_SCOPE_COMBINED,
)


class AuthRateLimit(Base):
    """One fixed-window failure bucket keyed by an HMAC digest.

    Raw emails, IP addresses and usernames are never stored here.  The
    composite primary key is the HMAC scope and digest, so concurrent workers
    can update one bucket atomically through PostgreSQL upsert semantics.
    """

    __tablename__ = "auth_rate_limits"
    __table_args__ = (
        CheckConstraint(
            "scope IN ('ip', 'identifier', 'combined')",
            name="auth_rate_limit_scope_valid",
        ),
        CheckConstraint(
            "failure_count >= 0",
            name="auth_rate_limit_failure_count_nonnegative",
        ),
        CheckConstraint(
            "char_length(key_hash) = 64",
            name="auth_rate_limit_key_hash_length",
        ),
        CheckConstraint(
            "blocked_until IS NULL OR blocked_until >= window_start",
            name="auth_rate_limit_block_after_window",
        ),
        CheckConstraint(
            "updated_at >= window_start",
            name="auth_rate_limit_updated_after_window",
        ),
        Index("ix_auth_rate_limits_updated_at", "updated_at"),
    )

    scope: Mapped[str] = mapped_column(String(16), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return f"<AuthRateLimit {self.scope!r} count={self.failure_count!r}>"
