"""Authenticated cart routes."""

from __future__ import annotations

from flask import flash, redirect, render_template, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.cart import cart_bp
from app.cart.forms import AddToCartForm, UpdateCartForm
from app.extensions import db
from app.services.cart import (
    CartError,
    CartItemNotFound,
    add_to_cart,
    calculate_subtotal,
    get_cart_for_user,
    get_or_create_cart,
    remove_cart_item,
    update_cart_item,
)


@cart_bp.get("")
@login_required
def view_cart() -> ResponseReturnValue:
    """Render the signed-in customer's cart."""
    get_or_create_cart(current_user.id)
    db.session.commit()
    cart = get_cart_for_user(current_user.id)
    if cart is None:
        raise RuntimeError("Cart could not be loaded after creation.")

    subtotal = calculate_subtotal(cart)
    has_unavailable = any(not item.is_purchasable for item in cart.items)
    return render_template(
        "cart/cart.html",
        cart=cart,
        subtotal=subtotal,
        has_unavailable=has_unavailable,
    )


@cart_bp.post("/add")
@login_required
def add_item() -> ResponseReturnValue:
    """Add a selected variant to the current user's cart."""
    form = AddToCartForm()
    if form.validate_on_submit():
        try:
            add_to_cart(current_user.id, form.variant_id.data, form.quantity.data)
        except CartError as exc:
            flash(str(exc), "error")
        else:
            flash("Added to your cart.", "success")
    else:
        flash("Select an available size, colour and quantity between 1 and 99.", "error")

    return redirect(url_for("cart.view_cart"))


@cart_bp.post("/update/<int:item_id>")
@login_required
def update_item(item_id: int) -> ResponseReturnValue:
    """Update the quantity of a cart line owned by the current user."""
    form = UpdateCartForm()
    if form.validate_on_submit():
        try:
            update_cart_item(current_user.id, item_id, form.quantity.data)
        except CartItemNotFound:
            flash("Cart item not found.", "error")
        except CartError as exc:
            flash(str(exc), "error")
        else:
            flash("Cart updated.", "success")
    else:
        flash("Enter a quantity between 1 and 99.", "error")

    return redirect(url_for("cart.view_cart"))


@cart_bp.post("/remove/<int:item_id>")
@login_required
def remove_item(item_id: int) -> ResponseReturnValue:
    """Remove a cart line owned by the current user."""
    try:
        remove_cart_item(current_user.id, item_id)
    except CartItemNotFound:
        flash("Cart item not found.", "error")
    except CartError as exc:
        flash(str(exc), "error")
    else:
        flash("Item removed from your cart.", "success")

    return redirect(url_for("cart.view_cart"))
