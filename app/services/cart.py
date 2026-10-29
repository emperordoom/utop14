"""Shopping cart operations with stock and ownership validation."""

from __future__ import annotations

from decimal import Decimal
from typing import Final

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import Cart, CartItem, Category, Product, ProductVariant

MAX_CART_QUANTITY: Final = 99
_CENT: Final = Decimal("0.01")


class CartError(Exception):
    """Base error for cart operations that cannot be completed."""


class CartItemNotFound(CartError):
    """Raised when a cart item does not exist for the requesting user."""


def _validate_quantity(value: object) -> int:
    """Return a valid positive cart quantity or raise ``CartError``."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise CartError("Quantity must be a whole number.")
    if value < 1 or value > MAX_CART_QUANTITY:
        raise CartError(f"Quantity must be between 1 and {MAX_CART_QUANTITY}.")
    return value


def _load_purchasable_variant(variant_id: int) -> ProductVariant | None:
    """Return an active variant whose product and category are active."""
    statement = (
        select(ProductVariant)
        .join(ProductVariant.product)
        .join(Product.category)
        .options(joinedload(ProductVariant.product).joinedload(Product.category))
        .where(
            ProductVariant.id == variant_id,
            ProductVariant.is_active.is_(True),
            Product.is_active.is_(True),
            Category.is_active.is_(True),
        )
    )
    return db.session.scalar(statement)


def get_cart_for_user(user_id: int) -> Cart | None:
    """Return the user's cart with lines and current catalog data eager-loaded."""
    statement = (
        select(Cart)
        .where(Cart.user_id == user_id)
        .options(
            selectinload(Cart.items)
            .joinedload(CartItem.variant)
            .joinedload(ProductVariant.product)
            .joinedload(Product.category)
        )
    )
    return db.session.scalar(statement)


def get_or_create_cart(user_id: int, *, for_update: bool = False) -> Cart:
    """Return the user's cart, creating exactly one row under concurrency.

    When ``for_update`` is true the cart row is locked before any caller can
    touch cart items.  This keeps every cart mutation in the same lock order as
    checkout: cart row first, then cart-item rows.
    """
    statement = select(Cart).where(Cart.user_id == user_id)
    if for_update:
        statement = statement.with_for_update()
    cart = db.session.scalar(statement)
    if cart is not None:
        return cart

    # PostgreSQL's unique user_id index plus ON CONFLICT makes concurrent
    # first visits safe without a read-then-insert race.
    db.session.execute(
        pg_insert(Cart)
        .values(user_id=user_id)
        .on_conflict_do_nothing(index_elements=[Cart.user_id])
    )
    statement = select(Cart).where(Cart.user_id == user_id)
    if for_update:
        statement = statement.with_for_update()
    cart = db.session.scalar(statement)
    if cart is None:
        raise CartError("Could not create a cart. Please try again.")
    return cart


def _lock_cart_for_user(user_id: int) -> Cart | None:
    """Lock the user's cart row before any cart-item operation."""
    return db.session.scalar(select(Cart).where(Cart.user_id == user_id).with_for_update())


def _touch_cart(cart_id: int) -> None:
    """Advance the cart's update timestamp after a line mutation."""
    db.session.execute(update(Cart).where(Cart.id == cart_id).values(updated_at=func.now()))


def add_to_cart(user_id: int, variant_id: int, quantity: int = 1) -> Cart:
    """Add a variant to the user's cart, merging duplicate variants atomically."""
    quantity = _validate_quantity(quantity)
    variant = _load_purchasable_variant(variant_id)
    if variant is None:
        raise CartError("That size and colour is not available.")

    if quantity > variant.stock:
        raise CartError(f"Only {variant.stock} available for {variant.size} / {variant.color}.")

    cart = get_or_create_cart(user_id, for_update=True)

    # The cart row is already locked, so the item upsert and timestamp update
    # follow the same cart -> cart_items order used by checkout.
    statement = (
        pg_insert(CartItem)
        .values(cart_id=cart.id, variant_id=variant.id, quantity=quantity)
        .on_conflict_do_update(
            index_elements=[CartItem.cart_id, CartItem.variant_id],
            set_={
                "quantity": CartItem.quantity + quantity,
                "updated_at": func.now(),
            },
        )
        .returning(CartItem.quantity)
    )
    new_quantity = db.session.scalar(statement)

    if new_quantity is None:
        db.session.rollback()
        raise CartError("Could not update your cart. Please try again.")
    if new_quantity > MAX_CART_QUANTITY:
        db.session.rollback()
        raise CartError(f"Quantity must be between 1 and {MAX_CART_QUANTITY}.")
    if new_quantity > variant.stock:
        db.session.rollback()
        raise CartError(f"Only {variant.stock} available for {variant.size} / {variant.color}.")

    _touch_cart(cart.id)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise CartError("Could not update your cart. Please try again.") from exc

    return cart


def update_cart_item(user_id: int, item_id: int, quantity: int) -> CartItem:
    """Set a cart line quantity after ownership, availability and stock checks."""
    quantity = _validate_quantity(quantity)
    cart = _lock_cart_for_user(user_id)
    if cart is None:
        db.session.rollback()
        raise CartItemNotFound("Cart item not found.")

    statement = (
        select(CartItem)
        .where(CartItem.id == item_id, CartItem.cart_id == cart.id)
        .with_for_update(of=CartItem)
    )
    item = db.session.scalar(statement)
    if item is None:
        db.session.rollback()
        raise CartItemNotFound("Cart item not found.")

    variant = _load_purchasable_variant(item.variant_id)
    if variant is None:
        db.session.rollback()
        raise CartError("That item is no longer available.")
    if quantity > variant.stock:
        db.session.rollback()
        raise CartError(f"Only {variant.stock} available for {variant.size} / {variant.color}.")

    item.quantity = quantity
    _touch_cart(item.cart_id)
    db.session.commit()
    return item


def remove_cart_item(user_id: int, item_id: int) -> None:
    """Delete one cart line owned by the requesting user."""
    cart = _lock_cart_for_user(user_id)
    if cart is None:
        db.session.rollback()
        raise CartItemNotFound("Cart item not found.")

    statement = (
        select(CartItem)
        .where(CartItem.id == item_id, CartItem.cart_id == cart.id)
        .with_for_update(of=CartItem)
    )
    item = db.session.scalar(statement)
    if item is None:
        db.session.rollback()
        raise CartItemNotFound("Cart item not found.")

    cart_id = item.cart_id
    db.session.delete(item)
    _touch_cart(cart_id)
    db.session.commit()


def clear_cart(user_id: int) -> int:
    """Remove all lines from the user's cart and return the deleted count."""
    cart = _lock_cart_for_user(user_id)
    if cart is None:
        return 0

    result = db.session.execute(delete(CartItem).where(CartItem.cart_id == cart.id))
    _touch_cart(cart.id)
    db.session.commit()
    return result.rowcount or 0


def calculate_subtotal(cart: Cart) -> Decimal:
    """Calculate the cart subtotal from current database product prices."""
    return cart.subtotal.quantize(_CENT)
