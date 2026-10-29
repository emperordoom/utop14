"""PostgreSQL-backed tests for the cart service."""

from __future__ import annotations

from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import func, select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import Cart, CartItem, Product, ProductVariant, User
from app.services.cart import (
    MAX_CART_QUANTITY,
    CartError,
    CartItemNotFound,
    add_to_cart,
    calculate_subtotal,
    clear_cart,
    get_cart_for_user,
    get_or_create_cart,
    remove_cart_item,
    update_cart_item,
)


def _variant(sku: str) -> ProductVariant:
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
    assert variant is not None
    return variant


def test_get_or_create_cart_is_idempotent(app: Flask, make_user) -> None:
    user: User = make_user(email="cart-one@example.com")

    first = get_or_create_cart(user.id)
    db.session.commit()
    second = get_or_create_cart(user.id)
    db.session.commit()

    assert first.id == second.id
    assert db.session.scalar(select(func.count(Cart.id))) == 1


def test_add_item_calculates_subtotal_from_database_price(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-add@example.com")
    variant = _variant("UT014-VT-WBK-M")

    add_to_cart(user.id, variant.id, 2)

    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.line_count == 1
    assert cart.item_count == 2
    assert cart.items[0].quantity == 2
    assert cart.items[0].unit_price == Decimal("75.00")
    assert cart.items[0].line_total == Decimal("150.00")
    assert calculate_subtotal(cart) == Decimal("150.00")


def test_adding_same_variant_merges_quantity(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-merge@example.com")
    variant = _variant("UT014-VT-WBK-M")

    add_to_cart(user.id, variant.id, 1)
    add_to_cart(user.id, variant.id, 2)

    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.line_count == 1
    assert cart.items[0].quantity == 3
    assert db.session.scalar(select(func.count(CartItem.id))) == 1


def test_update_quantity_and_remove_item(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-update@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)

    cart = get_cart_for_user(user.id)
    assert cart is not None
    item_id = cart.items[0].id

    update_cart_item(user.id, item_id, 4)
    refreshed = get_cart_for_user(user.id)
    assert refreshed is not None
    assert refreshed.items[0].quantity == 4

    remove_cart_item(user.id, item_id)
    after_remove = get_cart_for_user(user.id)
    assert after_remove is not None
    assert after_remove.items == []


def test_clear_cart_removes_all_lines(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-clear@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 1)
    add_to_cart(user.id, _variant("UT014-SH-FCH-M").id, 2)

    deleted = clear_cart(user.id)

    assert deleted == 2
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items == []


def test_empty_cart_subtotal_is_zero(app: Flask, make_user) -> None:
    user: User = make_user(email="cart-empty@example.com")
    cart = get_or_create_cart(user.id)
    db.session.commit()

    assert calculate_subtotal(cart) == Decimal("0.00")


def test_missing_variant_is_rejected(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-missing@example.com")

    with pytest.raises(CartError, match="not available"):
        add_to_cart(user.id, 999999, 1)


def test_inactive_product_is_rejected(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-inactive-product@example.com")
    variant = _variant("UT014-VT-WBK-M")
    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.is_active = False
    db.session.commit()

    with pytest.raises(CartError, match="not available"):
        add_to_cart(user.id, variant.id, 1)

    assert get_cart_for_user(user.id) is None


def test_inactive_variant_is_rejected(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-inactive-variant@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.is_active = False
    db.session.commit()

    with pytest.raises(CartError, match="not available"):
        add_to_cart(user.id, variant.id, 1)


def test_insufficient_stock_is_rejected(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-stock@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.stock = 1
    db.session.commit()

    with pytest.raises(CartError, match="Only 1 available"):
        add_to_cart(user.id, variant.id, 2)


@pytest.mark.parametrize("quantity", [0, -1, MAX_CART_QUANTITY + 1])
def test_quantity_must_be_positive_and_bounded(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
    quantity: int,
) -> None:
    user: User = make_user(email=f"cart-quantity-{quantity}@example.com")
    variant = _variant("UT014-VT-WBK-M")

    with pytest.raises(CartError, match="Quantity"):
        add_to_cart(user.id, variant.id, quantity)


def test_current_database_price_is_used_for_subtotal(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-price@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 2)

    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.price = Decimal("80.00")
    db.session.commit()

    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items[0].unit_price == Decimal("80.00")
    assert cart.subtotal == Decimal("160.00")


def test_update_quantity_above_stock_is_rejected(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    user: User = make_user(email="cart-update-stock@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.stock = 3
    db.session.commit()
    add_to_cart(user.id, variant.id, 1)

    item = db.session.scalar(select(CartItem))
    assert item is not None

    with pytest.raises(CartError, match="Only 3 available"):
        update_cart_item(user.id, item.id, 4)

    refreshed = db.session.get(CartItem, item.id)
    assert refreshed is not None
    assert refreshed.quantity == 1


def test_cross_user_cart_isolation(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    owner: User = make_user(email="cart-owner-one@example.com")
    other: User = make_user(email="cart-owner-two@example.com")
    add_to_cart(owner.id, _variant("UT014-VT-WBK-M").id, 2)

    owner_cart = get_cart_for_user(owner.id)
    other_cart = get_cart_for_user(other.id)
    assert owner_cart is not None
    assert other_cart is None

    item_id = owner_cart.items[0].id
    with pytest.raises(CartItemNotFound):
        update_cart_item(other.id, item_id, 1)
    with pytest.raises(CartItemNotFound):
        remove_cart_item(other.id, item_id)

    owner_cart = get_cart_for_user(owner.id)
    assert owner_cart is not None
    assert owner_cart.items[0].quantity == 2


def test_cross_user_carts_have_different_rows(
    app: Flask,
    seeded_catalog: SeedSummary,
    make_user,
) -> None:
    first_user: User = make_user(email="cart-row-one@example.com")
    second_user: User = make_user(email="cart-row-two@example.com")

    first = get_or_create_cart(first_user.id)
    second = get_or_create_cart(second_user.id)
    db.session.commit()

    assert first.id != second.id
    assert first.user_id != second.user_id


def test_item_not_found_errors_are_owned(
    app: Flask,
    make_user,
) -> None:
    user: User = make_user(email="cart-not-found@example.com")

    with pytest.raises(CartItemNotFound):
        update_cart_item(user.id, 999999, 1)
    with pytest.raises(CartItemNotFound):
        remove_cart_item(user.id, 999999)
