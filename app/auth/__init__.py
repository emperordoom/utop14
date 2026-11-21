"""Authentication blueprint and Flask-Login integration."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, request, url_for
from flask.typing import ResponseReturnValue

from app.auth.redirects import sanitized_request_next_target
from app.extensions import db, login_manager
from app.models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"


@login_manager.unauthorized_handler
def handle_unauthorized() -> ResponseReturnValue:
    """Redirect unauthenticated visitors to login with a sanitized ``next`` target.

    Sensitive security-event filter parameters are stripped before generating
    the 302 Location header so expired sessions never carry them into
    ``/auth/login?next=...`` or login access logs.
    """
    if login_manager.login_message:
        flash(
            str(login_manager.login_message),
            login_manager.login_message_category or "info",
        )
    safe_next = sanitized_request_next_target(request.path, request.query_string)
    if safe_next is not None:
        return redirect(url_for("auth.login", next=safe_next))
    return redirect(url_for("auth.login"))


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    """Load an active account from the session identifier.

    Inactive accounts are treated as anonymous immediately, so deactivating a
    user also invalidates an existing browser session.
    """
    try:
        user_pk = int(user_id)
    except (TypeError, ValueError):
        return None

    user = db.session.get(User, user_pk)
    if user is None or not user.is_active:
        return None
    return user


from app.auth import routes  # noqa: E402, F401
