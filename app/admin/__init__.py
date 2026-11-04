"""Administrative and operator blueprints."""

from __future__ import annotations

from flask import Blueprint

admin_bp = Blueprint("admin", __name__)

from app.admin import (  # noqa: E402, F401
    catalog_routes,
    payment_proof_routes,
    review_routes,
    routes,
)
