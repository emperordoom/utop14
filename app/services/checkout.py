"""Transactional checkout and order retrieval services."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from decimal import Decimal
from typing import Final

from sqlalchemy import delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import (
    Cart,
    CartItem,
    Category,
    Order,
    OrderItem,
    Product,
    ProductVariant,
)
from app.models.order import ORDER_STATUS_PENDING, PAYMENT_STATUS_UNPAID
from app.money import MoneyValidationError, validate_whole_rupiah

# All catalog, shipping, and order amounts are whole-rupiah IDR values.
SHIPPING_FLAT_IDR: Final = Decimal("15000.00")
FREE_SHIPPING_THRESHOLD_IDR: Final = Decimal("350000.00")


class CheckoutError(Exception):
    """Base error for a checkout that cannot be completed."""


class CartEmptyError(CheckoutError):
    """Raised when checkout is attempted without cart lines."""


class CartUnavailableError(CheckoutError):
    """Raised when a cart line's product, category or variant is inactive."""


class StockError(CheckoutError):
    """Raised when current stock cannot cover a cart line."""


class InvalidAmountError(CheckoutError):
    """Raised when a catalog price or calculated checkout amount is not valid whole rupiah."""


@dataclass(frozen=True, slots=True)
class CheckoutTotals:
    """Server-calculated monetary summary for a cart or order."""

    subtotal: Decimal
    shipping_cost: Decimal
    total: Decimal


def calculate_shipping(subtotal: Decimal) -> Decimal:
    """Return the flat IDR shipping fee, waived at or above the IDR threshold."""
    try:
        validated_subtotal = validate_whole_rupiah(
            subtotal,
            label="Subtotal",
            allow_zero=True,
        )
        if validated_subtotal >= FREE_SHIPPING_THRESHOLD_IDR:
            return Decimal("0.00")
        return validate_whole_rupiah(
            SHIPPING_FLAT_IDR,
            label="Shipping cost",
            allow_zero=True,
        )
    except (TypeError, MoneyValidationError) as exc:
        raise InvalidAmountError(str(exc)) from exc


def _calculate_item_amounts(
    items: list[CartItem],
) -> tuple[list[tuple[CartItem, Decimal, Decimal]], Decimal]:
    """Validate whole-rupiah unit prices, line totals and subtotal for cart items."""
    priced_items: list[tuple[CartItem, Decimal, Decimal]] = []
    subtotal = Decimal("0.00")

    try:
        for item in items:
            variant = item.variant
            product = variant.product if variant is not None else None
            raw_price = product.price if product is not None else Decimal("0.00")
            unit_price = validate_whole_rupiah(
                raw_price,
                label="Product price",
                allow_zero=True,
            )
            line_total = validate_whole_rupiah(
                unit_price * item.quantity,
                label="Line total",
                allow_zero=True,
            )
            priced_items.append((item, unit_price, line_total))
            subtotal += line_total

        validated_subtotal = validate_whole_rupiah(
            subtotal,
            label="Subtotal",
            allow_zero=True,
        )
    except (TypeError, MoneyValidationError) as exc:
        raise InvalidAmountError(str(exc)) from exc

    return priced_items, validated_subtotal


def calculate_totals(cart: Cart) -> CheckoutTotals:
    """Calculate a validated whole-rupiah summary from current database prices."""
    _, subtotal = _calculate_item_amounts(list(cart.items))
    shipping_cost = calculate_shipping(subtotal)
    try:
        total = validate_whole_rupiah(
            subtotal + shipping_cost,
            label="Order total",
            allow_zero=True,
        )
    except (TypeError, MoneyValidationError) as exc:
        raise InvalidAmountError(str(exc)) from exc
    return CheckoutTotals(
        subtotal=subtotal,
        shipping_cost=shipping_cost,
        total=total,
    )


def _load_cart_for_checkout(user_id: int) -> tuple[Cart, list[CartItem]]:
    """Lock the user's cart and its lines for one checkout transaction."""
    cart = db.session.scalar(select(Cart).where(Cart.user_id == user_id).with_for_update())
    if cart is None:
        raise CartEmptyError("Your cart is empty.")

    items = list(
        db.session.scalars(
            select(CartItem)
            .options(
                joinedload(CartItem.variant)
                .joinedload(ProductVariant.product)
                .joinedload(Product.category)
            )
            .where(CartItem.cart_id == cart.id)
            .order_by(CartItem.variant_id, CartItem.id)
            .with_for_update(of=CartItem)
        )
    )
    if not items:
        raise CartEmptyError("Your cart is empty.")
    return cart, items


def _validate_items(items: list[CartItem]) -> list[CartItem]:
    """Validate active catalog data and current stock for every cart line."""
    validated: list[CartItem] = []
    for item in items:
        variant = item.variant
        product = variant.product if variant is not None else None

        if variant is None or not variant.is_active or product is None:
            raise CartUnavailableError("An item in your cart is no longer available.")
        if not product.is_active or product.category is None or not product.category.is_active:
            raise CartUnavailableError(f"{product.name} is no longer available.")
        if item.quantity < 1:
            raise CheckoutError("Cart quantities must be positive.")
        if item.quantity > variant.stock:
            raise StockError(
                f"Only {variant.stock} left for {product.name} ({variant.size} / {variant.color})."
            )
        validated.append(item)

    return sorted(validated, key=lambda item: (item.variant_id, item.id))


def _generate_order_number() -> str:
    """Allocate a unique, non-sequential customer-facing order number."""
    for _ in range(5):
        candidate = f"UT014-{secrets.token_hex(6).upper()}"
        exists = db.session.scalar(select(Order.id).where(Order.order_number == candidate))
        if exists is None:
            return candidate
    raise CheckoutError("Could not allocate an order number. Please try again.")


def _decrement_stock(variant_id: int, quantity: int) -> bool:
    """Atomically decrement stock; return whether exactly one row changed."""
    result = db.session.execute(
        update(ProductVariant)
        .where(
            ProductVariant.id == variant_id,
            ProductVariant.is_active.is_(True),
            ProductVariant.stock >= quantity,
            ProductVariant.product.has(Product.is_active.is_(True)),
            ProductVariant.product.has(Product.category.has(Category.is_active.is_(True))),
        )
        .values(stock=ProductVariant.stock - quantity)
        .execution_options(synchronize_session=False)
    )
    return (result.rowcount or 0) == 1


def checkout(
    user_id: int,
    *,
    recipient_name: str,
    recipient_phone: str,
    shipping_address: str,
    shipping_city: str,
    shipping_postal_code: str,
) -> Order:
    """Create an order, snapshot lines, deduct stock and clear the cart atomically."""
    try:
        cart, items = _load_cart_for_checkout(user_id)
        items = _validate_items(items)

        priced_items, subtotal = _calculate_item_amounts(items)
        shipping_cost = calculate_shipping(subtotal)
        try:
            total = validate_whole_rupiah(
                subtotal + shipping_cost,
                label="Order total",
                allow_zero=True,
            )
        except (TypeError, MoneyValidationError) as exc:
            raise InvalidAmountError(str(exc)) from exc

        order = Order(
            order_number=_generate_order_number(),
            user_id=user_id,
            status=ORDER_STATUS_PENDING,
            payment_status=PAYMENT_STATUS_UNPAID,
            recipient_name=recipient_name,
            recipient_phone=recipient_phone,
            shipping_address=shipping_address,
            shipping_city=shipping_city,
            shipping_postal_code=shipping_postal_code,
            subtotal=subtotal,
            shipping_cost=shipping_cost,
            total=total,
        )
        db.session.add(order)
        db.session.flush()

        for item, unit_price, line_total in priced_items:
            variant = item.variant
            product = variant.product

            db.session.add(
                OrderItem(
                    order=order,
                    product_id=product.id,
                    variant_id=variant.id,
                    product_name=product.name,
                    sku=variant.sku,
                    size=variant.size,
                    color=variant.color,
                    unit_price=unit_price,
                    quantity=item.quantity,
                    line_total=line_total,
                )
            )

            if not _decrement_stock(variant.id, item.quantity):
                raise StockError(
                    f"{product.name} no longer has enough stock. Review your cart and try again."
                )

        db.session.execute(
            delete(CartItem)
            .where(CartItem.cart_id == cart.id)
            .execution_options(synchronize_session=False)
        )
        db.session.commit()
        return order
    except CheckoutError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise CheckoutError("Checkout could not be completed. Please try again.") from exc


def get_order_for_user(user_id: int, order_number: str) -> Order | None:
    """Return one order with historical lines only when the user owns it."""
    normalized = order_number.strip().upper()
    statement = (
        select(Order)
        .options(
            selectinload(Order.items),
            selectinload(Order.payments),
        )
        .where(Order.order_number == normalized, Order.user_id == user_id)
    )
    return db.session.scalar(statement)
