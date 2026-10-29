"""Integration tests for cart routes and product-page add-to-cart UI."""

from __future__ import annotations

from collections.abc import Callable

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import CartItem, ProductVariant, User
from app.services.cart import get_cart_for_user


def _variant(sku: str) -> ProductVariant:
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
    assert variant is not None
    return variant


def _add_via_route(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    variant_id: int,
    quantity: int = 1,
) -> object:
    return client.post(
        "/cart/add",
        data={
            "csrf_token": token_for("/cart"),
            "variant_id": str(variant_id),
            "quantity": str(quantity),
        },
    )


def test_cart_requires_login(client: FlaskClient) -> None:
    response = client.get("/cart")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_cart_add_requires_login_after_csrf(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    token = csrf_token("/auth/login")
    variant = _variant("UT014-VT-WBK-M")

    response = client.post(
        "/cart/add",
        data={"csrf_token": token, "variant_id": str(variant.id), "quantity": "1"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_cart_add_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="cart-csrf@example.com")
    login("cart-csrf@example.com")
    variant = _variant("UT014-VT-WBK-M")

    response = client.post(
        "/cart/add",
        data={"variant_id": str(variant.id), "quantity": "1"},
    )

    assert response.status_code == 400
    assert get_cart_for_user(user.id) is None


def test_product_page_exposes_add_to_cart_for_signed_in_users(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="product-cart@example.com")
    login("product-cart@example.com")

    html = client.get("/product/void-tee").get_data(as_text=True)

    assert "Add to cart" in html
    assert 'name="variant_id"' in html
    assert 'name="quantity"' in html
    assert "Sold out" in html
    assert "/static/css/cart.css" in html


def test_anonymous_product_page_prompts_sign_in(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    html = client.get("/product/void-tee").get_data(as_text=True)

    assert "Sign in to add" in html
    assert 'name="variant_id"' not in html


def test_add_item_and_merge_duplicate_variant_via_routes(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-add-route@example.com")
    login("cart-add-route@example.com")
    variant = _variant("UT014-VT-WBK-M")

    first = _add_via_route(client, csrf_token, variant_id=variant.id, quantity=1)
    assert first.status_code == 302

    html = client.get("/cart").get_data(as_text=True)
    assert "Void Tee" in html
    assert "1 item" in html
    assert "$75" in html

    second = _add_via_route(client, csrf_token, variant_id=variant.id, quantity=2)
    assert second.status_code == 302

    html = client.get("/cart").get_data(as_text=True)
    assert "1 line" in html
    assert "3 items" in html
    assert "$225" in html
    assert db.session.scalar(select(CartItem.id)) is not None


def test_update_cart_line_quantity_via_route(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-update-route@example.com")
    login("cart-update-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    _add_via_route(client, csrf_token, variant_id=variant.id, quantity=1)

    item = db.session.scalar(select(CartItem))
    assert item is not None

    response = client.post(
        f"/cart/update/{item.id}",
        data={"csrf_token": csrf_token("/cart"), "quantity": "4"},
    )
    assert response.status_code == 302

    html = client.get("/cart").get_data(as_text=True)
    assert "4 items" in html
    assert "$300" in html


def test_invalid_quantity_update_is_rejected(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-invalid-qty@example.com")
    login("cart-invalid-qty@example.com")
    variant = _variant("UT014-VT-WBK-M")
    _add_via_route(client, csrf_token, variant_id=variant.id, quantity=1)
    item = db.session.scalar(select(CartItem))
    assert item is not None

    response = client.post(
        f"/cart/update/{item.id}",
        data={"csrf_token": csrf_token("/cart"), "quantity": "0"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Enter a quantity between 1 and 99." in response.get_data(as_text=True)
    refreshed = db.session.get(CartItem, item.id)
    assert refreshed is not None
    assert refreshed.quantity == 1


def test_remove_cart_line_via_route(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-remove-route@example.com")
    login("cart-remove-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    _add_via_route(client, csrf_token, variant_id=variant.id, quantity=1)
    item = db.session.scalar(select(CartItem))
    assert item is not None

    response = client.post(
        f"/cart/remove/{item.id}",
        data={"csrf_token": csrf_token("/cart")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Your cart is empty" in html
    assert db.session.get(CartItem, item.id) is None


def test_cart_empty_state(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="cart-empty-route@example.com")
    login("cart-empty-route@example.com")

    response = client.get("/cart")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Your cart is empty" in html
    assert "Shop the drop" in html


def test_cart_references_its_stylesheet(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="cart-css@example.com")
    login("cart-css@example.com")

    html = client.get("/cart").get_data(as_text=True)
    assert "/static/css/cart.css" in html
    assert client.get("/static/css/cart.css").status_code == 200


def test_cross_user_cannot_update_another_cart_line(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-owner-route@example.com")
    make_user(email="cart-other-route@example.com")
    login("cart-owner-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    _add_via_route(client, csrf_token, variant_id=variant.id, quantity=2)
    item = db.session.scalar(select(CartItem))
    assert item is not None

    logout_token = csrf_token("/auth/account")
    client.post("/auth/logout", data={"csrf_token": logout_token})
    login("cart-other-route@example.com")

    response = client.post(
        f"/cart/update/{item.id}",
        data={"csrf_token": csrf_token("/cart"), "quantity": "1"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Cart item not found." in response.get_data(as_text=True)
    refreshed = db.session.get(CartItem, item.id)
    assert refreshed is not None
    assert refreshed.quantity == 2


def test_inactive_variant_add_is_rejected(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="cart-inactive-route@example.com")
    login("cart-inactive-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.is_active = False
    db.session.commit()

    response = client.post(
        "/cart/add",
        data={
            "csrf_token": csrf_token("/cart"),
            "variant_id": str(variant.id),
            "quantity": "1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "not available" in response.get_data(as_text=True).lower()
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items == []


def test_insufficient_stock_add_is_rejected(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-stock-route@example.com")
    login("cart-stock-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    variant.stock = 1
    db.session.commit()

    response = client.post(
        "/cart/add",
        data={
            "csrf_token": csrf_token("/cart"),
            "variant_id": str(variant.id),
            "quantity": "2",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Only 1 available" in response.get_data(as_text=True)


def test_sold_out_variant_add_is_rejected(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="cart-zero-stock@example.com")
    login("cart-zero-stock@example.com")
    variant = _variant("UT014-VT-WBK-XL")

    response = client.post(
        "/cart/add",
        data={
            "csrf_token": csrf_token("/cart"),
            "variant_id": str(variant.id),
            "quantity": "1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Only 0 available" in response.get_data(as_text=True)
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items == []


def test_sold_out_variant_option_is_disabled(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    seeded_catalog: SeedSummary,
) -> None:
    make_user(email="cart-sold-out@example.com")
    login("cart-sold-out@example.com")
    variant = _variant("UT014-VT-WBK-XL")

    html = client.get("/product/void-tee").get_data(as_text=True)
    assert f'value="{variant.id}" disabled' in html
