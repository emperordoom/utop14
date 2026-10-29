"""Server-side role authorization helpers."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

from flask import abort
from flask_login import current_user, login_required

from app.models.user import ROLE_LEVELS, User

P = ParamSpec("P")
R = TypeVar("R")


def role_required(minimum_role: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Require authentication and a minimum role level.

    The hierarchy is customer < operator < admin.  Unauthenticated visitors are
    redirected to the login page by Flask-Login; authenticated users below the
    required level receive HTTP 403.
    """
    if minimum_role not in ROLE_LEVELS:
        raise ValueError(f"Unknown role: {minimum_role!r}")

    def decorator(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        @login_required
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            user = current_user
            if not isinstance(user, User) or not user.has_role(minimum_role):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
