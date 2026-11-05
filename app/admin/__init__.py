"""Administrative and operator blueprints."""

from __future__ import annotations

from flask import Blueprint

from app.formatting import format_utc

admin_bp = Blueprint("admin", __name__)
admin_bp.add_app_template_filter(format_utc, "utc")

from app.admin import (  # noqa: E402, F401
    audit_routes,
    catalog_routes,
    payment_proof_routes,
    review_routes,
    routes,
    security_event_routes,
    user_routes,
)
