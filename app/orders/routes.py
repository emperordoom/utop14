"""Customer-facing order confirmation routes."""

from __future__ import annotations

from flask import abort, render_template
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.orders import orders_bp
from app.services.checkout import get_order_for_user


@orders_bp.get("/orders/<order_number>")
@login_required
def confirmation(order_number: str) -> ResponseReturnValue:
    """Show one order only to the customer who placed it."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    return render_template("orders/confirmation.html", order=order)
