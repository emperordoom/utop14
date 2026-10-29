"""Administrative and operator blueprints."""

from __future__ import annotations

from flask import Blueprint

admin_bp = Blueprint("admin", __name__)

from app.admin import routes  # noqa: E402, F401
