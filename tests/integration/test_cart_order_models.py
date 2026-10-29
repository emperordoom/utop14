"""PostgreSQL-backed tests for cart and order constraints."""

from __future__ import annotations

from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import (
    Cart,
    CartItem,
    Order,
    OrderItem,
    Product,
    ProductVariant,
    User,
)


def _order(user_id: int, *, number: str = "TEST-ORDER-1") -> Order:
    return Order(
        order_number=number,
        user_id=user_id,
        status="pending",
        payment_status="unpaid",
        recipient_name="Test Recipient",
        recipient_phone="+1 555 0100",
        shipping_address="14 After Hours Street",
        shipping_city="Night City",
        shipping_postal_code="01400",
        subtotal=Decimal("75.00"),
        shipping_cost=Decimal("12.00"),
        total=Decimal("87.00"),
    )


def _variant(sku: str) -> ProductVariant:
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
    assert variant is not None
    return variant


def test_one_cart_per_user_is_enforced(app: Flask, make_user) -> None:
    user: User = make_user(email="cart-owner@example.com")
    db.session.add(Cart(user_id=user.id))
    db.session.commit()

    db.session.add(Cart(user_id=user.id))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_cart_item_quantity_and_unique_variant_constraints(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-item@example.com")
    cart = Cart(user_id=user.id)
    variant = _variant("UT014-VT-WBK-M")
    db.session.add(cart)
    db.session.flush()

    db.session.add(CartItem(cart=cart, variant=variant, quantity=0))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    cart = Cart(user_id=user.id)
    db.session.add(cart)
    db.session.flush()
    db.session.add(CartItem(cart=cart, variant=variant, quantity=1))
    db.session.commit()

    db.session.add(CartItem(cart=cart, variant=variant, quantity=1))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_order_status_and_payment_constraints(
    app: Flask,
    make_user,
) -> None:
    user: User = make_user(email="order-status@example.com")

    bad_status = _order(user.id, number="TEST-STATUS-BAD")
    db.session.add(bad_status)
    db.session.flush()
    bad_status.status = "bogus"
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    bad_payment = _order(user.id, number="TEST-PAYMENT-BAD")
    db.session.add(bad_payment)
    db.session.flush()
    bad_payment.payment_status = "bogus"
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_order_monetary_constraints(
    app: Flask,
    make_user,
) -> None:
    user: User = make_user(email="order-money@example.com")

    order = _order(user.id, number="TEST-NEGATIVE-TOTAL")
    db.session.add(order)
    db.session.flush()
    order.total = Decimal("-0.01")
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_order_item_quantity_and_monetary_constraints(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="order-item-money@example.com")
    variant = _variant("UT014-VT-WBK-M")
    product = variant.product

    order = _order(user.id, number="TEST-ITEM-BAD")
    db.session.add(order)
    db.session.flush()
    db.session.add(
        OrderItem(
            order=order,
            product_id=product.id,
            variant_id=variant.id,
            product_name=product.name,
            sku=variant.sku,
            size=variant.size,
            color=variant.color,
            unit_price=Decimal("75.00"),
            quantity=0,
            line_total=Decimal("0.00"),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    order = _order(user.id, number="TEST-ITEM-NEGATIVE")
    db.session.add(order)
    db.session.flush()
    db.session.add(
        OrderItem(
            order=order,
            product_id=product.id,
            variant_id=variant.id,
            product_name=product.name,
            sku=variant.sku,
            size=variant.size,
            color=variant.color,
            unit_price=Decimal("-0.01"),
            quantity=1,
            line_total=Decimal("-0.01"),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_cart_deletion_cascades_to_items(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-cascade@example.com")
    cart = Cart(user_id=user.id)
    cart.items.append(CartItem(variant=_variant("UT014-VT-WBK-M"), quantity=2))
    db.session.add(cart)
    db.session.commit()
    item_id = cart.items[0].id

    db.session.delete(cart)
    db.session.commit()

    assert db.session.get(CartItem, item_id) is None


def test_order_item_keeps_snapshot_after_product_deletion(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="history@example.com")
    variant = _variant("UT014-VT-WBK-M")
    product = variant.product

    order = _order(user.id, number="TEST-HISTORY")
    db.session.add(order)
    db.session.flush()
    item = OrderItem(
        order=order,
        product_id=product.id,
        variant_id=variant.id,
        product_name=product.name,
        sku=variant.sku,
        size=variant.size,
        color=variant.color,
        unit_price=Decimal("75.00"),
        quantity=1,
        line_total=Decimal("75.00"),
    )
    db.session.add(item)
    db.session.commit()
    order_item_id = item.id

    db.session.delete(product)
    db.session.commit()

    historical = db.session.get(OrderItem, order_item_id)
    assert historical is not None
    assert historical.product_id is None
    assert historical.variant_id is None
    assert historical.product_name == "Void Tee"
    assert historical.sku == "UT014-VT-WBK-M"
    assert historical.unit_price == Decimal("75.00")
    assert db.session.get(Product, product.id) is None
