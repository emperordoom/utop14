"""Admin-only read-only security-event routes."""

from __future__ import annotations

from flask import abort, make_response, render_template, request
from flask.typing import ResponseReturnValue

from app.admin import admin_bp
from app.auth.permissions import role_required
from app.models.user import ROLE_ADMIN
from app.services.security_event_admin import (
    EVENT_TYPE_CHOICES,
    OUTCOME_CHOICES,
    REASON_GROUPS,
    AdminSecurityEventFilters,
    displayable_metadata,
    get_security_event,
    list_security_events,
    normalize_page,
)


@admin_bp.get("/admin/security-events")
@role_required(ROLE_ADMIN)
def security_event_list() -> ResponseReturnValue:
    """List and filter authentication security events newest first."""
    filters = AdminSecurityEventFilters.from_values(
        event_type=request.args.getlist("event_type"),
        outcome=request.args.getlist("outcome"),
        reason=request.args.getlist("reason"),
        date_from=request.args.getlist("date_from"),
        date_to=request.args.getlist("date_to"),
        request_id=request.args.getlist("request_id"),
        identifier_hash=request.args.getlist("identifier_hash"),
        actor_user_id=request.args.getlist("actor_user_id"),
        subject_user_id=request.args.getlist("subject_user_id"),
    )
    page = normalize_page(request.args.get("page", 1, type=int))
    pagination = list_security_events(filters, page=page)
    response = make_response(
        render_template(
            "admin/security_event_list.html",
            pagination=pagination,
            filters=filters,
            event_types=EVENT_TYPE_CHOICES,
            outcomes=OUTCOME_CHOICES,
            reason_groups=REASON_GROUPS,
        )
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


@admin_bp.get("/admin/security-events/<int:event_id>")
@role_required(ROLE_ADMIN)
def security_event_detail(event_id: int) -> ResponseReturnValue:
    """Render one read-only authentication security event."""
    event = get_security_event(event_id)
    if event is None:
        abort(404)

    response = make_response(
        render_template(
            "admin/security_event_detail.html",
            event=event,
            metadata_items=displayable_metadata(event.event_type, event.metadata_json),
        )
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
