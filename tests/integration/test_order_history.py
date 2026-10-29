"""Integration tests for customer order history."""

from __future__ import annotations

from collections.abc import Callable

from flask.testing import FlaskClient

from app.models import Order, User


def test_order_history_requires_login(client: FlaskClient) -> None:
    response = client.get("/orders")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_order_history_shows_only_the_current_users_orders(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    owner: User = make_user(email="history-owner@example.com")
    other: User = make_user(email="history-other@example.com")
    own_order = make_order(owner)
    other_order = make_order(other)

    login("history-owner@example.com")
    html = client.get("/orders").get_data(as_text=True)

    assert own_order.order_number in html
    assert other_order.order_number not in html


def test_order_history_sorts_newest_first(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="history-sort@example.com")
    first = make_order(user, sku="UT014-OC-JBK-OS")
    second = make_order(user, sku="UT014-OC-JBK-OS")

    login("history-sort@example.com")
    html = client.get("/orders").get_data(as_text=True)

    assert html.index(second.order_number) < html.index(first.order_number)


def test_order_history_pagination(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="history-pages@example.com")
    orders = [make_order(user, sku="UT014-OC-JBK-OS") for _ in range(11)]
    order_numbers = [order.order_number for order in orders]

    login("history-pages@example.com")
    first_page = client.get("/orders").get_data(as_text=True)
    second_page = client.get("/orders?page=2").get_data(as_text=True)

    assert "11 orders" in first_page
    assert first_page.count('class="order-card"') == 10
    assert second_page.count('class="order-card"') == 1
    assert order_numbers[-1] in first_page
    assert order_numbers[0] in second_page
    assert order_numbers[0] not in first_page


def test_order_history_empty_state(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="history-empty@example.com")
    login("history-empty@example.com")

    response = client.get("/orders")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "No orders yet" in html
    assert "Shop the drop" in html
    assert "/static/css/orders.css" in html
