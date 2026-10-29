"""Authentication blueprint and Flask-Login integration."""

from __future__ import annotations

from flask import Blueprint

from app.extensions import db, login_manager
from app.models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"


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
