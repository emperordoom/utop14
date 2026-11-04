"""Admin-only audit log list and detail routes."""

from __future__ import annotations

from flask import abort, render_template, request
from flask.typing import ResponseReturnValue

from app.admin import admin_bp
from app.auth.permissions import role_required
from app.models.audit_log import AUDIT_ACTIONS
from app.models.user import ROLE_ADMIN
from app.services.audit import (
    AdminAuditFilters,
    get_audit_log,
    list_audit_logs,
)


@admin_bp.get("/admin/audit-logs")
@role_required(ROLE_ADMIN)
def audit_log_list() -> ResponseReturnValue:
    """List audit records newest first with validated filters."""
    filters = AdminAuditFilters.from_values(
        action=request.args.get("action"),
        actor=request.args.get("actor"),
        target=request.args.get("target"),
        date_from=request.args.get("date_from"),
        date_to=request.args.get("date_to"),
        q=request.args.get("q"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_audit_logs(filters, page=page)
    return render_template(
        "admin/audit_log_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        actions=AUDIT_ACTIONS,
    )


@admin_bp.get("/admin/audit-logs/<int:log_id>")
@role_required(ROLE_ADMIN)
def audit_log_detail(log_id: int) -> ResponseReturnValue:
    """Render one audit record without any mutation controls."""
    log = get_audit_log(log_id)
    if log is None:
        abort(404)

    return render_template("admin/audit_log_detail.html", log=log)
