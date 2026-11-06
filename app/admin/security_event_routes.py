"""Admin-only read-only security-event routes.

Sensitive filters are never carried in the URL.  The browser holds only an
opaque random token in an HttpOnly cookie; the validated filter payload lives
in PostgreSQL and is scoped to the authenticated admin.
"""

from __future__ import annotations

from flask import (
    abort,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask.typing import ResponseReturnValue
from flask_login import current_user

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
from app.services.security_event_filter_state import (
    FILTER_STATE_COOKIE,
    FilterStateUnavailable,
    clear_filter_state_cookie,
    create_filter_state,
    delete_filter_state,
    load_filter_state,
    set_filter_state_cookie,
)

# Query parameters that used to carry sensitive filter values.  They are never
# echoed back, never copied into a redirect, and never kept in a URL.
_LEGACY_SENSITIVE_PARAMS = frozenset(
    {
        "event_type",
        "outcome",
        "reason",
        "date_from",
        "date_to",
        "request_id",
        "identifier_hash",
        "actor_user_id",
        "subject_user_id",
    }
)


def _clean_list_url() -> str:
    """Return the list URL with only a non-sensitive page parameter."""
    page = normalize_page(request.args.get("page", 1, type=int))
    if "page" in request.args:
        return url_for("admin.security_event_list", page=page)
    return url_for("admin.security_event_list")


def _form_filters() -> AdminSecurityEventFilters:
    """Build validated filters from the POST body (never from the URL)."""
    return AdminSecurityEventFilters.from_values(
        event_type=request.form.getlist("event_type"),
        outcome=request.form.getlist("outcome"),
        reason=request.form.getlist("reason"),
        date_from=request.form.getlist("date_from"),
        date_to=request.form.getlist("date_to"),
        request_id=request.form.getlist("request_id"),
        identifier_hash=request.form.getlist("identifier_hash"),
        actor_user_id=request.form.getlist("actor_user_id"),
        subject_user_id=request.form.getlist("subject_user_id"),
    )


def _render_list(filters: AdminSecurityEventFilters, page: int) -> ResponseReturnValue:
    pagination = list_security_events(filters, page=page)
    return make_response(
        render_template(
            "admin/security_event_list.html",
            pagination=pagination,
            filters=filters,
            event_types=EVENT_TYPE_CHOICES,
            outcomes=OUTCOME_CHOICES,
            reason_groups=REASON_GROUPS,
        )
    )


@admin_bp.get("/admin/security-events")
@role_required(ROLE_ADMIN)
def security_event_list() -> ResponseReturnValue:
    """List and filter authentication security events newest first."""
    if _LEGACY_SENSITIVE_PARAMS.intersection(request.args):
        # Never reflect old sensitive query parameters; send the browser to a
        # clean URL.  The old values are not copied into the Location header.
        # The active filter-state cookie is deliberately preserved: a legacy
        # link must not reset the admin's current filter state.
        return redirect(_clean_list_url(), code=303)

    token = request.cookies.get(FILTER_STATE_COOKIE)
    filters = (
        load_filter_state(token, current_user.id) if token is not None else None
    ) or AdminSecurityEventFilters()
    page = normalize_page(request.args.get("page", 1, type=int))
    return _render_list(filters, page)


@admin_bp.post("/admin/security-events/filters")
@role_required(ROLE_ADMIN)
def security_event_filter_apply() -> ResponseReturnValue:
    """Validate filters, store them server-side, and redirect to a clean URL."""
    filters = _form_filters()
    if not filters.is_valid:
        # Re-render the form with validation errors; nothing is stored and the
        # sensitive values stay in the POST body, not the URL.
        return _render_list(filters, 1)

    try:
        token = create_filter_state(current_user.id, filters)
    except FilterStateUnavailable:
        abort(503)

    response = redirect(url_for("admin.security_event_list"), code=303)
    set_filter_state_cookie(response, token)
    return response


@admin_bp.post("/admin/security-events/filters/clear")
@role_required(ROLE_ADMIN)
def security_event_filter_clear() -> ResponseReturnValue:
    """Delete the caller's stored filters and clear the opaque cookie."""
    delete_filter_state(request.cookies.get(FILTER_STATE_COOKIE), current_user.id)
    response = redirect(url_for("admin.security_event_list"), code=303)
    clear_filter_state_cookie(response)
    return response


@admin_bp.get("/admin/security-events/<int:event_id>")
@role_required(ROLE_ADMIN)
def security_event_detail(event_id: int) -> ResponseReturnValue:
    """Render one read-only authentication security event."""
    event = get_security_event(event_id)
    if event is None:
        abort(404)

    return make_response(
        render_template(
            "admin/security_event_detail.html",
            event=event,
            metadata_items=displayable_metadata(event.event_type, event.metadata_json),
        )
    )
