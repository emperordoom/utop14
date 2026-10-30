"""Integration tests for customer payment routes and simulation UI."""

from __future__ import annotations

import re
from collections.abc import Callable
from decimal import Decimal

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.extensions import db
from app.models import Order, Payment, User
from app.models.payment import PAYMENT_STATUS_FAILED, PAYMENT_STATUS_PAID
from app.models.user import ROLE_ADMIN, ROLE_OPERATOR


def _pay_form_tokens(client: FlaskClient, order_number: str) -> tuple[str, str]:
    response = client.get(f"/orders/{order_number}/pay")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    csrf_match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    key_match = re.search(r'name="idempotency_key"[^>]*value="([^"]+)"', html)
    assert csrf_match is not None
    assert key_match is not None
    return csrf_match.group(1), key_match.group(1)


def _create_payment(
    client: FlaskClient,
    order_number: str,
    *,
    extra: dict[str, str] | None = None,
) -> object:
    csrf, key = _pay_form_tokens(client, order_number)
    data = {"csrf_token": csrf, "idempotency_key": key}
    if extra:
        data.update(extra)
    return client.post(f"/orders/{order_number}/payments", data=data)


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


def test_payment_routes_require_login(client: FlaskClient, make_order, make_user) -> None:
    user: User = make_user(email="payment-login@example.com")
    order = make_order(user)

    assert client.get(f"/orders/{order.order_number}/pay").status_code == 302
    assert client.post(f"/orders/{order.order_number}/payments").status_code == 400
    assert client.get("/payments/PAY-MISSING").status_code == 302
    assert client.post("/payments/PAY-MISSING/simulate").status_code == 400


def test_pay_page_is_owner_only_and_shows_idr_amount(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    csrf_token: Callable[[str], str],
) -> None:
    owner: User = make_user(email="pay-page-owner@example.com")
    make_user(email="pay-page-other@example.com")
    order = make_order(owner)

    login("pay-page-owner@example.com")
    response = client.get(f"/orders/{order.order_number}/pay")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert order.order_number in html
    assert "SIMULATION ONLY — NO REAL MONEY" in html
    assert "Rp " in html
    assert 'name="idempotency_key"' in html
    assert "card" not in html.lower()
    assert "cvv" not in html.lower()

    _logout(client, csrf_token)
    login("pay-page-other@example.com")
    assert client.get(f"/orders/{order.order_number}/pay").status_code == 404


def test_pay_page_does_not_create_a_payment_attempt(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-get-no-mutation@example.com")
    order = make_order(user)
    login("payment-get-no-mutation@example.com")

    response = client.get(f"/orders/{order.order_number}/pay")

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(Payment.id))) == 0


def test_payment_creation_uses_server_amount_and_idr(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-create-route@example.com")
    order = make_order(user)
    login("payment-create-route@example.com")

    response = _create_payment(
        client,
        order.order_number,
        extra={"amount": "1.00", "currency": "USD", "status": "paid"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/payments/PAY-")
    payment = db.session.scalar(select(Payment))
    assert payment is not None
    assert payment.amount == order.total
    assert payment.amount != Decimal("1.00")
    assert payment.currency == "IDR"
    assert payment.status == "pending"
    assert payment.order_id == order.id


def test_pay_page_generates_a_fresh_idempotency_key(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-fresh-key@example.com")
    order = make_order(user)
    login("payment-fresh-key@example.com")

    _, first_key = _pay_form_tokens(client, order.order_number)
    _, second_key = _pay_form_tokens(client, order.order_number)

    assert first_key != second_key


def test_duplicate_payment_post_returns_existing_attempt(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-duplicate-route@example.com")
    order = make_order(user)
    login("payment-duplicate-route@example.com")
    csrf, key = _pay_form_tokens(client, order.order_number)

    first = client.post(
        f"/orders/{order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": key},
    )
    second = client.post(
        f"/orders/{order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": key},
    )

    assert first.status_code == 302
    assert second.status_code == 302
    assert first.headers["Location"] == second.headers["Location"]
    assert db.session.scalar(select(func.count(Payment.id))) == 1


def test_idempotency_key_flow_across_two_orders(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="payment-idem-route-flow@example.com")
    first_order = make_order(user)
    second_order = make_order(user)
    login("payment-idem-route-flow@example.com")
    csrf = csrf_token(f"/orders/{first_order.order_number}/pay")

    first = client.post(
        f"/orders/{first_order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": "test-idempotency-001"},
    )
    assert first.status_code == 302
    assert db.session.scalar(select(func.count(Payment.id))) == 1
    first_payment = db.session.scalar(select(Payment))
    assert first_payment is not None
    first_reference = first_payment.payment_reference
    assert first_reference in first.headers["Location"]

    repeated = client.post(
        f"/orders/{first_order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": "test-idempotency-001"},
    )
    assert repeated.status_code == 302
    assert repeated.headers["Location"] == first.headers["Location"]
    assert db.session.scalar(select(func.count(Payment.id))) == 1
    assert (
        db.session.scalar(
            select(Payment.payment_reference).where(Payment.payment_reference == first_reference)
        )
        == first_reference
    )

    new_key = client.post(
        f"/orders/{first_order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": "test-idempotency-002"},
    )
    assert new_key.status_code == 302
    assert new_key.headers["Location"] != first.headers["Location"]
    assert db.session.scalar(select(func.count(Payment.id))) == 2

    cross_order = client.post(
        f"/orders/{second_order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": "test-idempotency-001"},
        follow_redirects=True,
    )
    assert cross_order.status_code == 200
    assert "already been used for another order" in cross_order.get_data(as_text=True)
    assert db.session.scalar(select(func.count(Payment.id))) == 2
    assert db.session.scalar(select(Payment.id).where(Payment.order_id == second_order.id)) is None


def test_payment_creation_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-csrf-route@example.com")
    order = make_order(user)
    login("payment-csrf-route@example.com")

    response = client.post(
        f"/orders/{order.order_number}/payments",
        data={"idempotency_key": "csrf-missing-key"},
    )

    assert response.status_code == 400
    assert db.session.scalar(select(func.count(Payment.id))) == 0


def test_payment_detail_is_owner_only(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    csrf_token: Callable[[str], str],
) -> None:
    owner: User = make_user(email="payment-detail-owner@example.com")
    make_user(email="payment-detail-other@example.com")
    order = make_order(owner)
    payment = make_payment(owner, order=order)

    login("payment-detail-owner@example.com")
    response = client.get(f"/payments/{payment.payment_reference}")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert payment.payment_reference in html
    assert payment.amount == order.total
    assert "Rp " in html
    assert "SIMULATION ONLY — NO REAL MONEY" in html

    _logout(client, csrf_token)
    login("payment-detail-other@example.com")
    assert client.get(f"/payments/{payment.payment_reference}").status_code == 404


def test_successful_simulation_marks_order_paid(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="payment-simulate-success@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-simulate-success@example.com")

    response = client.post(
        f"/payments/{payment.payment_reference}/simulate",
        data={
            "csrf_token": csrf_token(f"/payments/{payment.payment_reference}"),
            "outcome": "success",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Simulated payment completed" in response.get_data(as_text=True)
    refreshed_payment = db.session.scalar(
        select(Payment).where(Payment.payment_reference == payment.payment_reference)
    )
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_PAID
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "paid"


def test_failed_simulation_leaves_order_unpaid(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    csrf_token: Callable[[str], str],
) -> None:
    user: User = make_user(email="payment-simulate-failure@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-simulate-failure@example.com")

    response = client.post(
        f"/payments/{payment.payment_reference}/simulate",
        data={
            "csrf_token": csrf_token(f"/payments/{payment.payment_reference}"),
            "outcome": "failure",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Simulated payment failed" in response.get_data(as_text=True)
    refreshed_payment = db.session.scalar(
        select(Payment).where(Payment.payment_reference == payment.payment_reference)
    )
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_FAILED
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "unpaid"


def test_simulation_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
) -> None:
    user: User = make_user(email="payment-simulate-csrf@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-simulate-csrf@example.com")

    response = client.post(
        f"/payments/{payment.payment_reference}/simulate",
        data={"outcome": "success"},
    )

    assert response.status_code == 400
    refreshed = db.session.get(Payment, payment.id)
    assert refreshed is not None
    assert refreshed.status == "pending"


def test_cross_user_cannot_simulate_payment(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    csrf_token: Callable[[str], str],
) -> None:
    owner: User = make_user(email="payment-sim-owner@example.com")
    make_user(email="payment-sim-other@example.com")
    order = make_order(owner)
    payment = make_payment(owner, order=order)

    login("payment-sim-other@example.com")
    response = client.post(
        f"/payments/{payment.payment_reference}/simulate",
        data={
            "csrf_token": csrf_token("/auth/account"),
            "outcome": "success",
        },
    )

    assert response.status_code == 404
    refreshed = db.session.get(Payment, payment.id)
    assert refreshed is not None
    assert refreshed.status == "pending"


def test_invalid_http_methods_are_rejected(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
) -> None:
    user: User = make_user(email="payment-methods@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-methods@example.com")

    assert client.get(f"/orders/{order.order_number}/payments").status_code == 405
    assert client.get(f"/payments/{payment.payment_reference}/simulate").status_code == 405
    assert client.post(f"/payments/{payment.payment_reference}").status_code == 405


def test_simulation_disabled_returns_404(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="payment-sim-disabled@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-sim-disabled@example.com")
    monkeypatch.setitem(app.config, "PAYMENT_SIMULATION_ENABLED", False)

    response = client.post(
        f"/payments/{payment.payment_reference}/simulate",
        data={
            "csrf_token": csrf_token("/auth/account"),
            "outcome": "success",
        },
    )

    assert response.status_code == 404
    refreshed = db.session.get(Payment, payment.id)
    assert refreshed is not None
    assert refreshed.status == "pending"


def test_production_payment_initiation_is_unavailable(
    app: Flask,
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="payment-production-unavailable@example.com")
    order = make_order(user)
    login("payment-production-unavailable@example.com")
    csrf, key = _pay_form_tokens(client, order.order_number)

    monkeypatch.setitem(app.config, "PAYMENT_PROVIDER", "")
    monkeypatch.setitem(app.config, "PAYMENT_SIMULATION_ENABLED", False)

    pay_page = client.get(f"/orders/{order.order_number}/pay")
    create_response = client.post(
        f"/orders/{order.order_number}/payments",
        data={"csrf_token": csrf, "idempotency_key": key},
    )

    assert pay_page.status_code == 503
    assert create_response.status_code == 503
    assert db.session.scalar(select(func.count(Payment.id))) == 0


def test_order_detail_shows_payment_action_and_attempts(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
) -> None:
    user: User = make_user(email="payment-order-detail@example.com")
    order = make_order(user)
    payment = make_payment(user, order=order)
    login("payment-order-detail@example.com")

    html = client.get(f"/orders/{order.order_number}").get_data(as_text=True)

    assert "Pay now" in html
    assert payment.payment_reference in html
    assert "SIMULATION ONLY — NO REAL MONEY" in html


@pytest.mark.parametrize("role", [ROLE_OPERATOR, ROLE_ADMIN])
def test_admin_order_detail_shows_payment_attempts_read_only(
    client: FlaskClient,
    login: Callable[..., object],
    make_user,
    make_order,
    make_payment,
    role: str,
) -> None:
    customer: User = make_user(email="payment-admin-customer@example.com")
    make_user(email=f"payment-admin-{role}@example.com", role=role)
    order = make_order(customer)
    payment = make_payment(customer, order=order)
    login(f"payment-admin-{role}@example.com")

    html = client.get(f"/admin/orders/{order.order_number}").get_data(as_text=True)

    assert payment.payment_reference in html
    assert "SIMULATION ONLY — NO REAL MONEY" in html
    assert "Simulation controls" not in html
