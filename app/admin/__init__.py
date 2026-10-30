"""Administrative and operator blueprints."""

from __future__ import annotations

from flask import Blueprint

admin_bp = Blueprint("admin", __name__)

from app.admin import catalog_routes, routes  # noqa: E402, F401
