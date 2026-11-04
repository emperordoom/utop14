"""Admin-only read-only security-event routes."""

from __future__ import annotations

from flask import render_template, request
from flask.typing import ResponseReturnValue

from app.admin import admin_bp
from app.auth.permissions import role_required
from app.models.user import ROLE_ADMIN
from app.services.security_event_admin import list_security_events, normalize_page


@admin_bp.get("/admin/security-events")
@role_required(ROLE_ADMIN)
def security_event_list() -> ResponseReturnValue:
    """List authentication security events newest first, 20 per page."""
    page = normalize_page(request.args.get("page", 1, type=int))
    pagination = list_security_events(page=page)
    return render_template("admin/security_event_list.html", pagination=pagination)
