"""Protected staff routes."""

from __future__ import annotations

from flask import render_template
from flask.typing import ResponseReturnValue

from app.admin import admin_bp
from app.auth.permissions import role_required
from app.models.user import ROLE_ADMIN, ROLE_OPERATOR
from app.services.admin import get_admin_stats


@admin_bp.get("/admin")
@role_required(ROLE_ADMIN)
def dashboard() -> ResponseReturnValue:
    """Render the admin-only dashboard with read-only aggregate counts."""
    return render_template("admin/dashboard.html", stats=get_admin_stats())


@admin_bp.get("/ops")
@role_required(ROLE_OPERATOR)
def operations() -> ResponseReturnValue:
    """Render the operator-level console without inventory write actions."""
    return render_template("admin/ops.html", stats=get_admin_stats())
