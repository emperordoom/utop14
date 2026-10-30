"""Protected staff routes."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user

from app.admin import admin_bp
from app.admin.forms import OrderStatusForm
from app.auth.permissions import role_required
from app.models.order import ORDER_STATUSES, PAYMENT_STATUSES
from app.models.user import ROLE_ADMIN, ROLE_OPERATOR
from app.services.admin import get_admin_stats
from app.services.orders import (
    OrderNotFound,
    OrderStateError,
    StaffOrderFilters,
    allowed_staff_transitions,
    get_staff_order,
    list_staff_orders,
    transition_staff_order,
)


@admin_bp.get("/admin")
@role_required(ROLE_ADMIN)
def dashboard() -> ResponseReturnValue:
    """Render the admin-only dashboard with read-only aggregate counts."""
    return render_template("admin/dashboard.html", stats=get_admin_stats())


@admin_bp.get("/ops")
@role_required(ROLE_OPERATOR)
def operations() -> ResponseReturnValue:
    """Render the operator-level console."""
    return render_template("admin/ops.html", stats=get_admin_stats())


@admin_bp.get("/admin/orders")
@role_required(ROLE_OPERATOR)
def order_list() -> ResponseReturnValue:
    """List all orders for operators and admins with filters and pagination."""
    filters = StaffOrderFilters.from_values(
        status=request.args.get("status"),
        payment_status=request.args.get("payment_status"),
        q=request.args.get("q"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_staff_orders(filters, page=page)
    return render_template(
        "admin/order_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        statuses=ORDER_STATUSES,
        payment_statuses=PAYMENT_STATUSES,
    )


@admin_bp.get("/admin/orders/<order_number>")
@role_required(ROLE_OPERATOR)
def order_detail(order_number: str) -> ResponseReturnValue:
    """Render one order with its customer, snapshot lines and status controls."""
    order = get_staff_order(order_number)
    if order is None:
        abort(404)

    form = OrderStatusForm()
    allowed = allowed_staff_transitions(order)
    form.status.choices = [(status, status.replace("_", " ").title()) for status in allowed]
    return render_template(
        "admin/order_detail.html",
        order=order,
        form=form,
        allowed_transitions=allowed,
    )


@admin_bp.post("/admin/orders/<order_number>/status")
@role_required(ROLE_OPERATOR)
def update_order_status(order_number: str) -> ResponseReturnValue:
    """Apply one validated lifecycle transition with CSRF protection."""
    form = OrderStatusForm()
    form.status.choices = [(status, status.replace("_", " ").title()) for status in ORDER_STATUSES]

    if not form.validate_on_submit():
        flash("Choose a valid order status.", "error")
        return redirect(url_for("admin.order_detail", order_number=order_number))

    try:
        transition_staff_order(
            order_number,
            form.status.data,
            actor_user_id=current_user.id,
            reason=form.reason.data,
        )
    except OrderNotFound:
        abort(404)
    except OrderStateError as exc:
        flash(str(exc), "error")
    else:
        flash("Order status updated.", "success")

    return redirect(url_for("admin.order_detail", order_number=order_number))
