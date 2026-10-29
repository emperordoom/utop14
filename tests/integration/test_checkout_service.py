"""PostgreSQL-backed tests for transactional checkout."""

from __future__ import annotations

from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import func, select

import app.services.checkout as checkout_service
from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import CartItem, Order, OrderItem, Product, ProductVariant, User
from app.models.order import ORDER_STATUS_PENDING, PAYMENT_STATUS_UNPAID
from app.services.cart import add_to_cart, get_cart_for_user
from app.services.checkout import (
    CartEmptyError,
    CartUnavailableError,
    StockError,
    checkout,
    get_order_for_user,
)


def _variant(sku: str) -> ProductVariant:
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
    assert variant is not None
    return variant


def _checkout(user_id: int) -> Order:
    return checkout(
        user_id,
        recipient_name="Test Recipient",
        recipient_phone="+1 555 0100",
        shipping_address="14 After Hours Street",
        shipping_city="Night City",
        shipping_postal_code="01400",
    )


def test_successful_checkout_creates_order_snapshots_and_deducts_stock(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-success@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 2)

    order = _checkout(user.id)

    assert order.order_number.startswith("UT014-")
    assert order.status == ORDER_STATUS_PENDING
    assert order.payment_status == PAYMENT_STATUS_UNPAID
    assert order.subtotal == Decimal("150.00")
    assert order.shipping_cost == Decimal("12.00")
    assert order.total == Decimal("162.00")

    stored = get_order_for_user(user.id, order.order_number)
    assert stored is not None
    assert len(stored.items) == 1
    line = stored.items[0]
    assert line.product_name == "Void Tee"
    assert line.sku == "UT014-VT-WBK-M"
    assert line.size == "M"
    assert line.color == "Washed Black"
    assert line.unit_price == Decimal("75.00")
    assert line.quantity == 2
    assert line.line_total == Decimal("150.00")

    refreshed_variant = db.session.get(ProductVariant, variant.id)
    assert refreshed_variant is not None
    assert refreshed_variant.stock == 16

    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items == []


def test_free_shipping_threshold_uses_server_subtotal(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-free-shipping@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 1)
    add_to_cart(user.id, _variant("UT014-SH-FCH-M").id, 1)

    order = _checkout(user.id)

    assert order.subtotal == Decimal("255.00")
    assert order.shipping_cost == Decimal("0.00")
    assert order.total == Decimal("255.00")


def test_checkout_uses_current_price_and_preserves_historical_snapshot(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-price@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)

    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.price = Decimal("80.00")
    db.session.commit()

    order = _checkout(user.id)
    assert order.subtotal == Decimal("80.00")
    assert order.items[0].unit_price == Decimal("80.00")

    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.price = Decimal("95.00")
    db.session.commit()

    stored = get_order_for_user(user.id, order.order_number)
    assert stored is not None
    assert stored.items[0].unit_price == Decimal("80.00")
    assert stored.total == Decimal("92.00")


def test_empty_cart_cannot_be_checked_out(
    app: Flask,
    make_user,
) -> None:
    user: User = make_user(email="checkout-empty@example.com")

    with pytest.raises(CartEmptyError):
        _checkout(user.id)

    assert db.session.scalar(select(func.count(Order.id))) == 0


def test_inactive_product_blocks_checkout(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-inactive-product@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)

    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.is_active = False
    db.session.commit()

    with pytest.raises(CartUnavailableError):
        _checkout(user.id)

    assert db.session.scalar(select(func.count(Order.id))) == 0
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 1


def test_inactive_variant_blocks_checkout(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-inactive-variant@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)

    variant.is_active = False
    db.session.commit()

    with pytest.raises(CartUnavailableError):
        _checkout(user.id)

    assert db.session.scalar(select(func.count(Order.id))) == 0


def test_insufficient_stock_blocks_checkout(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="checkout-stock@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 2)

    variant.stock = 1
    db.session.commit()

    with pytest.raises(StockError):
        _checkout(user.id)

    assert db.session.scalar(select(func.count(Order.id))) == 0
    refreshed = db.session.get(ProductVariant, variant.id)
    assert refreshed is not None
    assert refreshed.stock == 1
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 1


def test_stock_update_failure_rolls_back_entire_checkout(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="checkout-rollback@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)

    monkeypatch.setattr("app.services.checkout._decrement_stock", lambda *_: False)

    with pytest.raises(StockError):
        _checkout(user.id)

    assert db.session.scalar(select(func.count(Order.id))) == 0
    assert db.session.scalar(select(func.count(OrderItem.id))) == 0
    refreshed = db.session.get(ProductVariant, variant.id)
    assert refreshed is not None
    assert refreshed.stock == 18
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 1


def test_checkout_rolls_back_successful_stock_decrement_when_later_line_fails(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="checkout-two-line-rollback@example.com")
    first_variant = _variant("UT014-VT-WBK-M")
    second_variant = _variant("UT014-SH-FCH-M")
    first_id = first_variant.id
    second_id = second_variant.id
    initial_first_stock = first_variant.stock
    initial_second_stock = second_variant.stock

    add_to_cart(user.id, first_id, 1)
    add_to_cart(user.id, second_id, 1)

    original_decrement = checkout_service._decrement_stock
    calls: list[int] = []
    results: list[bool] = []

    def fail_second_decrement(variant_id: int, quantity: int) -> bool:
        calls.append(variant_id)
        if len(calls) == 1:
            result = original_decrement(variant_id, quantity)
            results.append(result)
            return result
        results.append(False)
        return False

    monkeypatch.setattr(
        checkout_service,
        "_decrement_stock",
        fail_second_decrement,
    )

    with pytest.raises(StockError):
        _checkout(user.id)

    assert calls == sorted(calls)
    assert results == [True, False]
    assert db.session.scalar(select(func.count(Order.id))) == 0
    assert db.session.scalar(select(func.count(OrderItem.id))) == 0

    db.session.expire_all()
    refreshed_first = db.session.get(ProductVariant, first_id)
    refreshed_second = db.session.get(ProductVariant, second_id)
    assert refreshed_first is not None
    assert refreshed_second is not None
    assert refreshed_first.stock == initial_first_stock
    assert refreshed_second.stock == initial_second_stock

    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 2
    quantities = {item.variant_id: item.quantity for item in cart.items}
    assert quantities == {
        first_id: 1,
        second_id: 1,
    }


def test_second_checkout_cannot_oversell_remaining_stock(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    first: User = make_user(email="checkout-first@example.com")
    second: User = make_user(email="checkout-second@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.stock = 1
    db.session.commit()

    add_to_cart(first.id, variant.id, 1)
    add_to_cart(second.id, variant.id, 1)

    _checkout(first.id)

    with pytest.raises(StockError):
        _checkout(second.id)

    assert db.session.scalar(select(func.count(Order.id))) == 1
    refreshed = db.session.get(ProductVariant, variant.id)
    assert refreshed is not None
    assert refreshed.stock == 0
    second_cart = get_cart_for_user(second.id)
    assert second_cart is not None
    assert len(second_cart.items) == 1


def test_order_is_only_visible_to_its_owner(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    owner: User = make_user(email="order-owner@example.com")
    other: User = make_user(email="order-other@example.com")
    add_to_cart(owner.id, _variant("UT014-VT-WBK-M").id, 1)
    order = _checkout(owner.id)

    assert get_order_for_user(owner.id, order.order_number) is not None
    assert get_order_for_user(other.id, order.order_number) is None


def test_checkout_clears_only_the_owner_cart(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    first: User = make_user(email="clear-first@example.com")
    second: User = make_user(email="clear-second@example.com")
    add_to_cart(first.id, _variant("UT014-VT-WBK-M").id, 1)
    add_to_cart(second.id, _variant("UT014-SH-FCH-M").id, 1)

    _checkout(first.id)

    first_cart = get_cart_for_user(first.id)
    second_cart = get_cart_for_user(second.id)
    assert first_cart is not None
    assert first_cart.items == []
    assert second_cart is not None
    assert len(second_cart.items) == 1
    assert db.session.scalar(select(func.count(CartItem.id))) == 1
