"""Admin-only user directory, profile, status and role services."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import load_only

from app.extensions import db
from app.models import User
from app.models.user import ROLE_ADMIN, ROLES
from app.services.profiles import (
    CONFLICT_MESSAGE,
    ProfileValidationError,
    normalize_full_name,
    normalize_profile_email,
)

_MAX_FILTER_LENGTH: Final = 80
_USER_COLUMNS = (
    User.id,
    User.email,
    User.full_name,
    User.role,
    User.is_active,
    User.created_at,
    User.updated_at,
    User.last_login_at,
    User.avatar_filename,
)


class UserAdminError(Exception):
    """Base error for admin user-management operations."""


class UserAdminNotFound(UserAdminError):
    """Raised when the requested account does not exist."""


class UserAdminValidationError(UserAdminError):
    """Raised when submitted account data fails server-side validation."""


class UserAdminConflictError(UserAdminError):
    """Raised when an email conflicts with another account."""


class UserAdminStateError(UserAdminError):
    """Raised when a status or role change would remove admin access."""


@dataclass(frozen=True, slots=True)
class AdminUserFilters:
    """Normalized admin user-list filters."""

    query: str | None = None
    role: str | None = None
    status: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        q: str | None = None,
        role: str | None = None,
        status: str | None = None,
    ) -> AdminUserFilters:
        """Build filters from untrusted query-string values."""
        normalized_query = q.strip()[:_MAX_FILTER_LENGTH] if isinstance(q, str) else None
        normalized_role = role.strip().lower() if isinstance(role, str) else None
        if normalized_role not in ROLES:
            normalized_role = None

        normalized_status = status.strip().lower() if isinstance(status, str) else None
        if normalized_status not in {"active", "inactive"}:
            normalized_status = None

        return cls(
            query=normalized_query or None,
            role=normalized_role,
            status=normalized_status,
        )

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {
            "q": self.query,
            "role": self.role,
            "status": self.status,
        }
        return {key: value for key, value in values.items() if value}


@dataclass(frozen=True, slots=True)
class AdminUserChangeResult:
    """Outcome of one account status or role change."""

    user: User
    message: str
    category: str = "success"


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_admin_users(
    filters: AdminUserFilters,
    *,
    page: int = 1,
    per_page: int = 20,
):
    """Return a paginated, filtered account directory."""
    conditions = []
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                User.full_name.ilike(pattern, escape="\\"),
                User.email.ilike(pattern, escape="\\"),
            )
        )
    if filters.role is not None:
        conditions.append(User.role == filters.role)
    if filters.status == "active":
        conditions.append(User.is_active.is_(True))
    elif filters.status == "inactive":
        conditions.append(User.is_active.is_(False))

    statement = (
        select(User)
        .options(load_only(*_USER_COLUMNS))
        .where(*conditions)
        .order_by(User.created_at.desc(), User.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_admin_user(user_id: int) -> User | None:
    """Return one account without loading its password hash."""
    statement = select(User).options(load_only(*_USER_COLUMNS)).where(User.id == user_id)
    return db.session.scalar(statement)


def count_active_admins() -> int:
    """Return the number of active admin accounts."""
    return (
        db.session.scalar(
            select(func.count(User.id)).where(
                User.role == ROLE_ADMIN,
                User.is_active.is_(True),
            )
        )
        or 0
    )


def update_user_by_admin(
    user_id: int,
    *,
    full_name: object,
    email: object,
) -> User:
    """Update only the account's full name and email.

    Role, active status, password material and avatar fields are never accepted
    as inputs to this operation.
    """
    try:
        cleaned_name = normalize_full_name(full_name)
        cleaned_email = normalize_profile_email(email)
    except ProfileValidationError as exc:
        raise UserAdminValidationError(str(exc)) from exc

    try:
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise UserAdminNotFound("Account not found.")

        duplicate = db.session.scalar(
            select(User.id)
            .where(
                func.lower(User.email) == cleaned_email.lower(),
                User.id != user_id,
            )
            .limit(1)
        )
        if duplicate is not None:
            raise UserAdminConflictError(CONFLICT_MESSAGE)

        user.full_name = cleaned_name
        user.email = cleaned_email
        db.session.commit()
        return user
    except UserAdminError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        db.session.rollback()
        raise UserAdminConflictError(CONFLICT_MESSAGE) from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise UserAdminError("Account details could not be saved. Please try again.") from exc


def _lock_active_admins() -> list[User]:
    """Lock active admin rows in a stable order for last-admin checks."""
    statement = (
        select(User)
        .where(
            User.role == ROLE_ADMIN,
            User.is_active.is_(True),
        )
        .order_by(User.id)
        .with_for_update()
    )
    return list(db.session.scalars(statement).all())


def _assert_can_remove_admin_access(
    *,
    actor_user_id: int,
    target: User,
    active_admins: list[User],
) -> None:
    """Reject self-lockout and any change that would leave zero active admins."""
    if target.role != ROLE_ADMIN or not target.is_active:
        return
    if actor_user_id == target.id:
        raise UserAdminStateError("You cannot remove your own administrative access.")
    if len(active_admins) <= 1:
        raise UserAdminStateError("At least one active admin account must remain.")


def set_user_active(
    actor_user_id: int,
    user_id: int,
    *,
    is_active: bool,
) -> AdminUserChangeResult:
    """Activate or deactivate one account without deleting any history."""
    try:
        active_admins = _lock_active_admins()
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise UserAdminNotFound("Account not found.")

        if user.is_active is is_active:
            db.session.commit()
            state = "active" if is_active else "inactive"
            return AdminUserChangeResult(
                user,
                f"Account is already {state}.",
                "info",
            )

        if not is_active:
            _assert_can_remove_admin_access(
                actor_user_id=actor_user_id,
                target=user,
                active_admins=active_admins,
            )

        user.is_active = is_active
        db.session.commit()
        return AdminUserChangeResult(
            user,
            "Account activated." if is_active else "Account deactivated.",
            "success",
        )
    except UserAdminError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise UserAdminError("Account status could not be updated. Please try again.") from exc


def set_user_role(
    actor_user_id: int,
    user_id: int,
    *,
    role: object,
) -> AdminUserChangeResult:
    """Change one account's role within the existing role hierarchy."""
    if not isinstance(role, str) or role not in ROLES:
        raise UserAdminValidationError("Choose a valid role.")

    try:
        active_admins = _lock_active_admins()
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise UserAdminNotFound("Account not found.")

        if user.role == role:
            db.session.commit()
            return AdminUserChangeResult(
                user,
                f"Account already has the {role} role.",
                "info",
            )

        if user.role == ROLE_ADMIN and role != ROLE_ADMIN:
            _assert_can_remove_admin_access(
                actor_user_id=actor_user_id,
                target=user,
                active_admins=active_admins,
            )

        user.role = role
        db.session.commit()
        return AdminUserChangeResult(
            user,
            f"Role updated to {role}.",
            "success",
        )
    except UserAdminError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise UserAdminError("Account role could not be updated. Please try again.") from exc
