"""Integration tests for checkout and order confirmation routes."""

from __future__ import annotations

import re
from collections.abc import Callable
from decimal import Decimal

from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import Order, Product, ProductVariant, User
from app.services.cart import add_to_cart, get_cart_for_user


def _variant(sku: str) -> ProductVariant:
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == sku))
    assert variant is not None
    return variant


def _checkout_data(token: str, **overrides: str) -> dict[str, str]:
    data = {
        "csrf_token": token,
        "recipient_name": "Test Recipient",
        "recipient_phone": "+1 555 0100",
        "shipping_address": "14 After Hours Street",
        "shipping_city": "Night City",
        "shipping_postal_code": "01400",
    }
    data.update(overrides)
    return data


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


def test_checkout_requires_login(client: FlaskClient) -> None:
    response = client.get("/checkout")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_checkout_empty_cart_redirects_to_cart(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="checkout-empty-route@example.com")
    login("checkout-empty-route@example.com")

    response = client.get("/checkout")

    assert response.status_code == 302
    assert response.headers["Location"] == "/cart"


def test_checkout_get_renders_form_and_server_totals(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(
        email="checkout-form@example.com",
        full_name="Form Customer",
    )
    login("checkout-form@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 2)

    response = client.get("/checkout")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Shipping details" in html
    assert 'value="Form Customer"' in html
    assert "UT014-VT-WBK-M" not in html  # checkout summary uses names, not SKUs
    assert "Void Tee" in html
    assert "Rp 150" in html
    assert "Rp 12" in html
    assert "Rp 162" in html
    assert "/static/css/cart.css" in html


def test_checkout_rejects_invalid_address(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-invalid@example.com")
    login("checkout-invalid@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 1)

    response = client.post(
        "/checkout",
        data=_checkout_data(
            csrf_token("/checkout"),
            recipient_name="",
            recipient_phone="abc",
            shipping_postal_code="",
        ),
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "This field is required." in html or "Enter a valid phone number." in html
    assert db.session.scalar(select(func.count(Order.id))) == 0
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 1


def test_checkout_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-no-csrf@example.com")
    login("checkout-no-csrf@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 1)

    response = client.post(
        "/checkout",
        data={
            "recipient_name": "Test Recipient",
            "recipient_phone": "+1 555 0100",
            "shipping_address": "14 After Hours Street",
            "shipping_city": "Night City",
            "shipping_postal_code": "01400",
        },
    )

    assert response.status_code == 400
    assert db.session.scalar(select(func.count(Order.id))) == 0


def test_checkout_success_creates_order_and_confirmation(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-success-route@example.com")
    login("checkout-success-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 2)

    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/checkout")),
    )

    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith("/orders/UT014-")
    order_number = location.rsplit("/", 1)[-1]
    assert re.fullmatch(r"UT014-[0-9A-F]{12}", order_number)

    order = db.session.scalar(select(Order).where(Order.order_number == order_number))
    assert order is not None
    assert order.subtotal == 150
    assert order.shipping_cost == 12
    assert order.total == 162
    assert order.status == "pending"
    assert order.payment_status == "unpaid"

    refreshed_variant = db.session.get(ProductVariant, variant.id)
    assert refreshed_variant is not None
    assert refreshed_variant.stock == 16
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert cart.items == []

    confirmation = client.get(location)
    assert confirmation.status_code == 200
    html = confirmation.get_data(as_text=True)
    assert order_number in html
    assert "Signal" in html
    assert "Void Tee" in html
    assert "UT014-VT-WBK-M" in html
    assert "Rp 150" in html
    assert "Rp 12" in html
    assert "Rp 162" in html
    assert "Pending" in html
    assert "Unpaid" in html


def test_checkout_ignores_browser_supplied_prices(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-tamper@example.com")
    login("checkout-tamper@example.com")
    add_to_cart(user.id, _variant("UT014-VT-WBK-M").id, 2)

    response = client.post(
        "/checkout",
        data=_checkout_data(
            csrf_token("/checkout"),
            subtotal="1.00",
            shipping_cost="0.00",
            total="1.00",
            unit_price="1.00",
        ),
    )

    assert response.status_code == 302
    order = db.session.scalar(select(Order))
    assert order is not None
    assert order.subtotal == 150
    assert order.shipping_cost == 12
    assert order.total == 162


def test_checkout_inactive_product_is_rejected(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-inactive-route@example.com")
    login("checkout-inactive-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)
    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.is_active = False
    db.session.commit()

    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/checkout")),
    )

    assert response.status_code == 200
    assert "no longer available" in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(Order.id))) == 0
    cart = get_cart_for_user(user.id)
    assert cart is not None
    assert len(cart.items) == 1


def test_checkout_insufficient_stock_is_rejected(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="checkout-stock-route@example.com")
    login("checkout-stock-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 2)
    variant.stock = 1
    db.session.commit()

    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/checkout")),
    )

    assert response.status_code == 200
    assert "Only 1 left" in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(Order.id))) == 0
    refreshed = db.session.get(ProductVariant, variant.id)
    assert refreshed is not None
    assert refreshed.stock == 1


def test_checkout_empty_cart_post_redirects(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
) -> None:
    make_user(email="checkout-empty-post@example.com")
    login("checkout-empty-post@example.com")

    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/auth/account")),
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/cart"
    assert db.session.scalar(select(func.count(Order.id))) == 0


def test_order_confirmation_requires_login(client: FlaskClient) -> None:
    response = client.get("/orders/UT014-AAAAAAAAAAAA")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_order_confirmation_is_owner_only(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    owner: User = make_user(email="order-owner-route@example.com")
    make_user(email="order-other-route@example.com")
    login("order-owner-route@example.com")
    add_to_cart(owner.id, _variant("UT014-VT-WBK-M").id, 1)
    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/checkout")),
    )
    assert response.status_code == 302
    order_url = response.headers["Location"]

    _logout(client, csrf_token)
    login("order-other-route@example.com")

    assert client.get(order_url).status_code == 404


def test_unknown_order_returns_404(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="order-unknown@example.com")
    login("order-unknown@example.com")

    assert client.get("/orders/UT014-FFFFFFFFFFFF").status_code == 404


def test_authenticated_navigation_includes_cart(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="nav-cart@example.com")
    login("nav-cart@example.com")

    html = client.get("/").get_data(as_text=True)
    assert 'href="/cart"' in html


def test_order_snapshot_survives_later_catalog_change(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    csrf_token: Callable[[str], str],
    seeded_catalog: SeedSummary,
) -> None:
    user: User = make_user(email="order-snapshot-route@example.com")
    login("order-snapshot-route@example.com")
    variant = _variant("UT014-VT-WBK-M")
    add_to_cart(user.id, variant.id, 1)
    response = client.post(
        "/checkout",
        data=_checkout_data(csrf_token("/checkout")),
    )
    assert response.status_code == 302
    order_url = response.headers["Location"]

    product = db.session.get(Product, variant.product_id)
    assert product is not None
    product.name = "Renamed Product"
    product.price = Decimal("999.00")
    db.session.commit()

    html = client.get(order_url).get_data(as_text=True)
    assert "Void Tee" in html
    assert "Renamed Product" not in html
    assert "Rp 75" in html
    assert "Rp 999" not in html
