"""Authenticated checkout routes."""

from __future__ import annotations

from flask import flash, redirect, render_template, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.checkout import checkout_bp
from app.checkout.forms import CheckoutForm
from app.services.cart import get_cart_for_user
from app.services.checkout import (
    CheckoutError,
    calculate_totals,
    checkout,
)


def _checkout_context(form: CheckoutForm) -> dict[str, object] | None:
    """Build the checkout page context, or ``None`` when the cart is empty."""
    cart = get_cart_for_user(current_user.id)
    if cart is None or not cart.items:
        return None

    return {
        "form": form,
        "cart": cart,
        "totals": calculate_totals(cart),
        "has_unavailable": any(not item.is_purchasable for item in cart.items),
    }


@checkout_bp.get("")
@login_required
def view_checkout() -> ResponseReturnValue:
    """Render the checkout form for a non-empty cart."""
    form = CheckoutForm()
    form.recipient_name.data = current_user.full_name

    context = _checkout_context(form)
    if context is None:
        flash("Your cart is empty.", "info")
        return redirect(url_for("cart.view_cart"))

    return render_template("checkout/checkout.html", **context)


@checkout_bp.post("")
@login_required
def place_order() -> ResponseReturnValue:
    """Validate the destination and create the order transactionally."""
    form = CheckoutForm()
    if not form.validate_on_submit():
        context = _checkout_context(form)
        if context is None:
            flash("Your cart is empty.", "info")
            return redirect(url_for("cart.view_cart"))
        return render_template("checkout/checkout.html", **context), 200

    try:
        order = checkout(
            current_user.id,
            recipient_name=form.recipient_name.data,
            recipient_phone=form.recipient_phone.data,
            shipping_address=form.shipping_address.data,
            shipping_city=form.shipping_city.data,
            shipping_postal_code=form.shipping_postal_code.data,
        )
    except CheckoutError as exc:
        flash(str(exc), "error")
        context = _checkout_context(form)
        if context is None:
            return redirect(url_for("cart.view_cart"))
        return (
            render_template(
                "checkout/checkout.html",
                checkout_error=str(exc),
                **context,
            ),
            200,
        )

    return redirect(url_for("orders.confirmation", order_number=order.order_number))
