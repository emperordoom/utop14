"""Integration tests for customer order cancellation."""

from __future__ import annotations

import threading
from collections.abc import Callable

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.extensions import db
from app.models import Order, OrderItem, Product, ProductVariant, User
from app.services.orders import OrderStateError, cancel_customer_order


def _variant_and_stock(order_id: int) -> tuple[int, int]:
    variant_id = db.session.scalar(
        select(OrderItem.variant_id).where(OrderItem.order_id == order_id).limit(1)
    )
    assert variant_id is not None
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    return variant.id, variant.stock


def test_customer_can_cancel_pending_unpaid_order_and_restore_stock(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="cancel-success@example.com")
    order = make_order(user, quantity=2)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number

    login("cancel-success@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={
            "csrf_token": csrf_token(f"/orders/{order_number}"),
            "reason": "Changed my mind",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Cancelled" in html
    assert "Changed my mind" in html

    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "cancelled"
    assert refreshed.cancelled_at is not None
    assert refreshed.cancelled_at.tzinfo is not None
    assert refreshed.cancelled_by_user_id == user.id
    assert refreshed.cancellation_reason == "Changed my mind"
    assert refreshed.payment_status == "unpaid"

    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order + 2


@pytest.mark.parametrize(
    "status",
    ["processing", "shipped", "delivered", "cancelled"],
)
def test_customer_cannot_cancel_non_pending_orders(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
    status: str,
) -> None:
    user: User = make_user(email=f"cancel-{status}@example.com")
    order = make_order(user, status=status)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number

    login(f"cancel-{status}@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={"csrf_token": csrf_token("/auth/account")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == status
    assert refreshed.cancelled_at is None
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order


def test_customer_cannot_cancel_paid_pending_order(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="cancel-paid@example.com")
    order = make_order(user, payment_status="paid")
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number

    login("cancel-paid@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={"csrf_token": csrf_token("/auth/account")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"
    assert "Only pending unpaid orders can be cancelled." in response.get_data(as_text=True)
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order


def test_cross_user_cancellation_returns_404_and_changes_nothing(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    owner: User = make_user(email="cancel-owner@example.com")
    make_user(email="cancel-other@example.com")
    order = make_order(owner)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number

    login("cancel-other@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={"csrf_token": csrf_token("/auth/account")},
    )

    assert response.status_code == 404
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order


def test_cancellation_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="cancel-csrf@example.com")
    order = make_order(user)
    order_number = order.order_number

    login("cancel-csrf@example.com")
    response = client.post(f"/orders/{order_number}/cancel", data={})

    assert response.status_code == 400
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"


def test_cancellation_rolls_back_when_stock_restoration_fails(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="cancel-rollback@example.com")
    order = make_order(user)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number

    monkeypatch.setattr(
        "app.services.orders._restore_variant_stock",
        lambda *_: False,
    )

    login("cancel-rollback@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={"csrf_token": csrf_token(f"/orders/{order_number}")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"
    assert refreshed.cancelled_at is None
    assert refreshed.cancelled_by_user_id is None
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order


def test_cancellation_skips_deleted_variant_without_crashing(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="cancel-deleted-variant@example.com")
    order = make_order(user)
    order_number = order.order_number
    variant_id = db.session.scalar(
        select(OrderItem.variant_id).where(OrderItem.order_id == order.id).limit(1)
    )
    assert variant_id is not None
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    product = db.session.get(Product, variant.product_id)
    assert product is not None

    db.session.delete(product)
    db.session.commit()

    login("cancel-deleted-variant@example.com")
    response = client.post(
        f"/orders/{order_number}/cancel",
        data={"csrf_token": csrf_token(f"/orders/{order_number}")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "cancelled"
    item = db.session.scalar(select(OrderItem).where(OrderItem.order_id == order.id))
    assert item is not None
    assert item.variant_id is None


def test_concurrent_cancellation_restores_stock_only_once(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="cancel-concurrent@example.com")
    order = make_order(user)
    order_id = order.id
    order_number = order.order_number
    variant_id, stock_after_order = _variant_and_stock(order_id)

    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[str] = []

    def attempt_cancel() -> None:
        with app.app_context():
            barrier.wait()
            try:
                cancel_customer_order(user.id, order_number)
                results.append("cancelled")
            except OrderStateError:
                results.append("rejected")
            except Exception as exc:  # pragma: no cover - diagnostic safety
                errors.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=attempt_cancel) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert sorted(results) == ["cancelled", "rejected"]

    db.session.expire_all()
    refreshed = db.session.get(Order, order_id)
    assert refreshed is not None
    assert refreshed.status == "cancelled"
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order + 1
