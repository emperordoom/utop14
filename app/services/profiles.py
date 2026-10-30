"""Customer profile updates with server-side validation and transactions."""

from __future__ import annotations

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.extensions import db
from app.models import User
from app.models.user import normalize_email

MAX_FULL_NAME = 120
MAX_EMAIL = 255
CONFLICT_MESSAGE = "An account with that email already exists."


class ProfileError(Exception):
    """Base error for profile operations that cannot be completed."""


class ProfileValidationError(ProfileError):
    """Raised when submitted profile values fail server-side validation."""


class ProfileConflictError(ProfileError):
    """Raised when an email conflicts with another account."""


def normalize_full_name(value: object) -> str:
    """Return a whitespace-normalized full name or raise a validation error."""
    if not isinstance(value, str):
        raise ProfileValidationError("Full name is required.")
    cleaned = " ".join(value.split())
    if not cleaned:
        raise ProfileValidationError("Full name is required.")
    if len(cleaned) > MAX_FULL_NAME:
        raise ProfileValidationError(f"Full name must be {MAX_FULL_NAME} characters or fewer.")
    return cleaned


def normalize_profile_email(value: object) -> str:
    """Return a validated, normalized email or raise a validation error."""
    if not isinstance(value, str):
        raise ProfileValidationError("Enter a valid email address.")
    cleaned = normalize_email(value)
    if not cleaned:
        raise ProfileValidationError("Enter a valid email address.")
    try:
        validated = validate_email(cleaned, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ProfileValidationError("Enter a valid email address.") from exc

    normalized = normalize_email(validated.normalized)
    if len(normalized) > MAX_EMAIL:
        raise ProfileValidationError(f"Email must be {MAX_EMAIL} characters or fewer.")
    return normalized


def update_profile(user_id: int, *, full_name: object, email: object) -> User:
    """Update only the current user's full name and email.

    The user row is locked and the uniqueness check is repeated inside the
    transaction.  Role, active status and password material are never accepted
    as inputs to this service.
    """
    cleaned_name = normalize_full_name(full_name)
    cleaned_email = normalize_profile_email(email)

    try:
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise ProfileValidationError("Account not found.")

        duplicate = db.session.scalar(
            select(User.id)
            .where(
                func.lower(User.email) == cleaned_email.lower(),
                User.id != user_id,
            )
            .limit(1)
        )
        if duplicate is not None:
            raise ProfileConflictError(CONFLICT_MESSAGE)

        user.full_name = cleaned_name
        user.email = cleaned_email
        _commit_or_raise()
    except ProfileError:
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise ProfileError("Profile could not be saved. Please try again.") from exc
    return user


def _commit_or_raise() -> None:
    """Commit the profile transaction and translate database failures."""
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise ProfileConflictError(CONFLICT_MESSAGE) from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise ProfileError("Profile could not be saved. Please try again.") from exc
