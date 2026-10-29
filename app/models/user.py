"""User account model and role constants."""

from __future__ import annotations

from datetime import datetime
from typing import Final

from flask_login import UserMixin
from sqlalchemy import Boolean, CheckConstraint, DateTime, Index, String, text, true
from sqlalchemy.orm import Mapped, mapped_column, validates
from werkzeug.security import check_password_hash, generate_password_hash

from app.models.base import Base, TimestampMixin

ROLE_CUSTOMER: Final = "customer"
ROLE_OPERATOR: Final = "operator"
ROLE_ADMIN: Final = "admin"

ROLES: Final[tuple[str, ...]] = (ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_ADMIN)
ROLE_LEVELS: Final[dict[str, int]] = {
    ROLE_CUSTOMER: 10,
    ROLE_OPERATOR: 20,
    ROLE_ADMIN: 30,
}


def normalize_email(value: str) -> str:
    """Return a trimmed, lower-cased email address for storage and lookup."""
    return value.strip().lower()


class User(UserMixin, TimestampMixin, Base):
    """An authenticated UTOP14 account with a server-controlled role."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('customer', 'operator', 'admin')",
            name="role_valid",
        ),
        Index("ix_users_role_is_active", "role", "is_active"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ROLE_CUSTOMER,
        server_default=text("'customer'"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    @validates("email")
    def _normalize_email(self, _key: str, value: str) -> str:
        return normalize_email(value)

    def set_password(self, password: str) -> None:
        """Hash and store a plaintext password without retaining the original."""
        if not password or not password.strip():
            raise ValueError("Password must not be empty.")
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
        """Return whether a candidate password matches the stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def has_role(self, minimum_role: str) -> bool:
        """Return whether this user meets the requested role level."""
        try:
            required_level = ROLE_LEVELS[minimum_role]
        except KeyError as exc:
            raise ValueError(f"Unknown role: {minimum_role!r}") from exc
        return ROLE_LEVELS.get(self.role, 0) >= required_level

    @property
    def is_admin(self) -> bool:
        """Whether this account has the exact admin role."""
        return self.role == ROLE_ADMIN

    @property
    def is_operator(self) -> bool:
        """Whether this account can access operator-level pages."""
        return self.has_role(ROLE_OPERATOR)

    def __repr__(self) -> str:
        return f"<User {self.email!r} role={self.role!r}>"
