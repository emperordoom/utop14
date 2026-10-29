"""Integration tests for operator/admin order management."""

from __future__ import annotations

import threading
from collections.abc import Callable

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.extensions import db
from app.models import Order, OrderItem, ProductVariant, User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.orders import OrderStateError, transition_staff_order


def _post_status(
    client: FlaskClient,
    token_for: Callable[[str], str],
    order_number: str,
    status: str,
    *,
    reason: str | None = None,
) -> object:
    return client.post(
        f"/admin/orders/{order_number}/status",
        data={
            "csrf_token": token_for(f"/admin/orders/{order_number}"),
            "status": status,
            "reason": reason or "",
        },
        follow_redirects=True,
    )


def _variant_and_stock(order_id: int) -> tuple[int, int]:
    variant_id = db.session.scalar(
        select(OrderItem.variant_id).where(OrderItem.order_id == order_id).limit(1)
    )
    assert variant_id is not None
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    return variant.id, variant.stock


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (ROLE_CUSTOMER, 403),
        (ROLE_OPERATOR, 200),
        (ROLE_ADMIN, 200),
    ],
)
def test_order_management_authorization_matrix(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    role: str,
    expected: int,
) -> None:
    make_user(email=f"orders-{role}@example.com", role=role)
    login(f"orders-{role}@example.com")

    assert client.get("/admin/orders").status_code == expected


def test_operator_order_filters_and_search(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="orders-filter@example.com")
    pending = make_order(user, sku="UT014-OC-JBK-OS")
    processing = make_order(user, sku="UT014-OC-JBK-OS", status="processing")
    paid = make_order(
        user,
        sku="UT014-OC-JBK-OS",
        status="processing",
        payment_status="paid",
    )

    make_user(email="orders-filter-operator@example.com", role=ROLE_OPERATOR)
    login("orders-filter-operator@example.com")

    status_html = client.get("/admin/orders?status=processing").get_data(as_text=True)
    assert processing.order_number in status_html
    assert paid.order_number in status_html
    assert pending.order_number not in status_html

    payment_html = client.get("/admin/orders?payment_status=paid").get_data(as_text=True)
    assert paid.order_number in payment_html
    assert pending.order_number not in payment_html

    search_html = client.get(
        "/admin/orders",
        query_string={"q": pending.order_number[-6:]},
    ).get_data(as_text=True)
    assert pending.order_number in search_html
    assert processing.order_number not in search_html


def test_operator_order_detail_contains_customer_and_snapshots(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    customer: User = make_user(email="order-detail-customer@example.com")
    make_user(email="order-detail-operator@example.com", role=ROLE_OPERATOR)
    order = make_order(customer)
    login("order-detail-operator@example.com")

    response = client.get(f"/admin/orders/{order.order_number}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert order.order_number in html
    assert customer.email in html
    assert customer.full_name in html
    assert "Void Tee" in html
    assert "Shipping address" in html
    assert "Update status" in html


def test_operator_can_progress_order_through_valid_lifecycle(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    make_user(email="lifecycle-operator@example.com", role=ROLE_OPERATOR)
    order = make_order(make_user(email="lifecycle-owner@example.com"))
    order_number = order.order_number
    login("lifecycle-operator@example.com")

    _post_status(client, csrf_token, order_number, "processing")
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "processing"
    assert refreshed.payment_status == "unpaid"

    _post_status(client, csrf_token, order_number, "shipped")
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "shipped"

    _post_status(client, csrf_token, order_number, "delivered")
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "delivered"


@pytest.mark.parametrize(
    ("current_status", "target_status"),
    [
        ("pending", "shipped"),
        ("processing", "pending"),
        ("shipped", "processing"),
        ("delivered", "processing"),
        ("cancelled", "processing"),
    ],
)
def test_operator_cannot_apply_invalid_transitions(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
    current_status: str,
    target_status: str,
) -> None:
    user: User = make_user(email=f"invalid-{current_status}@example.com")
    make_user(
        email=f"invalid-operator-{current_status}@example.com",
        role=ROLE_OPERATOR,
    )
    order = make_order(user, status=current_status)
    order_number = order.order_number
    login(f"invalid-operator-{current_status}@example.com")

    response = _post_status(client, csrf_token, order_number, target_status)

    assert response.status_code == 200
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == current_status


def test_operator_can_cancel_pending_order_and_restore_stock(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    customer: User = make_user(email="staff-cancel-customer@example.com")
    operator: User = make_user(
        email="staff-cancel-operator@example.com",
        role=ROLE_OPERATOR,
    )
    order = make_order(customer, quantity=2)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number
    login("staff-cancel-operator@example.com")

    response = _post_status(
        client,
        csrf_token,
        order_number,
        "cancelled",
        reason="Customer requested cancellation",
    )

    assert response.status_code == 200
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "cancelled"
    assert refreshed.cancelled_by_user_id == operator.id
    assert refreshed.cancellation_reason == "Customer requested cancellation"
    assert refreshed.payment_status == "unpaid"
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order + 2


def test_operator_can_cancel_processing_unpaid_order_and_restore_stock(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    customer: User = make_user(email="staff-processing-customer@example.com")
    operator: User = make_user(
        email="staff-processing-operator@example.com",
        role=ROLE_OPERATOR,
    )
    order = make_order(customer, status="processing", quantity=1)
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number
    login("staff-processing-operator@example.com")

    response = _post_status(
        client,
        csrf_token,
        order_number,
        "cancelled",
        reason="Processing stopped before dispatch",
    )

    assert response.status_code == 200
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "cancelled"
    assert refreshed.cancelled_by_user_id == operator.id
    assert refreshed.cancellation_reason == "Processing stopped before dispatch"
    assert refreshed.payment_status == "unpaid"
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order + 1


def test_operator_cannot_cancel_paid_order(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="staff-paid-customer@example.com")
    make_user(email="staff-paid-operator@example.com", role=ROLE_OPERATOR)
    order = make_order(user, payment_status="paid")
    variant_id, stock_after_order = _variant_and_stock(order.id)
    order_number = order.order_number
    login("staff-paid-operator@example.com")

    response = _post_status(client, csrf_token, order_number, "cancelled")

    assert response.status_code == 200
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.stock == stock_after_order


def test_order_status_update_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="status-csrf-customer@example.com")
    make_user(email="status-csrf-operator@example.com", role=ROLE_OPERATOR)
    order = make_order(user)
    order_number = order.order_number
    login("status-csrf-operator@example.com")

    response = client.post(
        f"/admin/orders/{order_number}/status",
        data={"status": "processing"},
    )

    assert response.status_code == 400
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    assert refreshed.status == "pending"


def test_admin_order_list_pagination(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    user: User = make_user(email="orders-pagination-customer@example.com")
    make_user(email="orders-pagination-admin@example.com", role=ROLE_ADMIN)
    orders = [make_order(user, sku="UT014-OC-JBK-OS") for _ in range(21)]
    order_numbers = [order.order_number for order in orders]

    login("orders-pagination-admin@example.com")
    first_page = client.get("/admin/orders").get_data(as_text=True)
    second_page = client.get("/admin/orders?page=2").get_data(as_text=True)

    assert first_page.count('class="staff-order-row"') == 20
    assert second_page.count('class="staff-order-row"') == 1
    assert order_numbers[-1] in first_page
    assert order_numbers[0] in second_page


def test_concurrent_status_updates_are_serialized(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
) -> None:
    customer: User = make_user(email="status-concurrent-customer@example.com")
    operator: User = make_user(
        email="status-concurrent-operator@example.com",
        role=ROLE_OPERATOR,
    )
    order = make_order(customer)
    order_id = order.id
    order_number = order.order_number

    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[str] = []

    def attempt_transition() -> None:
        with app.app_context():
            barrier.wait()
            try:
                transition_staff_order(
                    order_number,
                    "processing",
                    actor_user_id=operator.id,
                )
                results.append("updated")
            except OrderStateError:
                results.append("rejected")
            except Exception as exc:  # pragma: no cover - diagnostic safety
                errors.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=attempt_transition) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert sorted(results) == ["rejected", "updated"]

    db.session.expire_all()
    refreshed = db.session.get(Order, order_id)
    assert refreshed is not None
    assert refreshed.status == "processing"
