"""Customer-facing order history, detail and cancellation routes."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.orders import orders_bp
from app.orders.forms import CancelOrderForm
from app.services.checkout import get_order_for_user
from app.services.orders import (
    OrderNotFound,
    OrderStateError,
    cancel_customer_order,
    customer_can_cancel,
    list_customer_orders,
)
from app.services.payments import can_pay_order, payment_provider_available


@orders_bp.get("/orders")
@login_required
def history() -> ResponseReturnValue:
    """Render the signed-in customer's paginated order history."""
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_customer_orders(current_user.id, page=page)
    return render_template("orders/history.html", pagination=pagination)


@orders_bp.get("/orders/<order_number>")
@login_required
def confirmation(order_number: str) -> ResponseReturnValue:
    """Show one order only to the customer who placed it."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    return render_template(
        "orders/confirmation.html",
        order=order,
        cancel_form=CancelOrderForm(),
        can_cancel=customer_can_cancel(order),
        can_pay=can_pay_order(order),
        payments_available=payment_provider_available(),
    )


@orders_bp.post("/orders/<order_number>/cancel")
@login_required
def cancel(order_number: str) -> ResponseReturnValue:
    """Cancel the owner's pending unpaid order and restore stock atomically."""
    form = CancelOrderForm()
    if not form.validate_on_submit():
        flash("Cancellation reason must be 500 characters or fewer.", "error")
        return redirect(url_for("orders.confirmation", order_number=order_number))

    try:
        cancel_customer_order(
            current_user.id,
            order_number,
            reason=form.reason.data,
        )
    except OrderNotFound:
        abort(404)
    except OrderStateError as exc:
        flash(str(exc), "error")
    else:
        flash("Order cancelled. Stock has been restored.", "success")

    return redirect(url_for("orders.confirmation", order_number=order_number))
