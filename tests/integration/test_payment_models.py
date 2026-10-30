"""PostgreSQL-backed tests for payment model constraints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Order, Payment, User
from app.models.payment import (
    PAYMENT_CURRENCY_IDR,
    PAYMENT_METHOD_SIMULATED,
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_PENDING,
)


def _payment(
    order: Order,
    *,
    reference: str,
    idempotency_key: str,
    status: str = PAYMENT_STATUS_PENDING,
    provider_reference: str | None = None,
    amount: Decimal = Decimal("87.00"),
    currency: str = PAYMENT_CURRENCY_IDR,
) -> Payment:
    return Payment(
        payment_reference=reference,
        order=order,
        provider=PAYMENT_PROVIDER_SIMULATED,
        payment_method=PAYMENT_METHOD_SIMULATED,
        amount=amount,
        currency=currency,
        status=status,
        idempotency_key=idempotency_key,
        provider_reference=provider_reference,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
    )


def test_payment_reference_must_be_unique(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-ref-unique@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-DUPLICATE",
            idempotency_key="idem-one",
        )
    )
    db.session.commit()

    db.session.add(
        _payment(
            order,
            reference="PAY-DUPLICATE",
            idempotency_key="idem-two",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_idempotency_key_is_unique_per_order(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-idempotency@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-IDEM-ONE",
            idempotency_key="same-key",
        )
    )
    db.session.commit()

    db.session.add(
        _payment(
            order,
            reference="PAY-IDEM-TWO",
            idempotency_key="same-key",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_provider_reference_is_unique_when_present(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-provider-ref@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-PROVIDER-ONE",
            idempotency_key="provider-one",
            provider_reference="SIM-PROVIDER-DUPLICATE",
        )
    )
    db.session.commit()

    db.session.add(
        _payment(
            order,
            reference="PAY-PROVIDER-TWO",
            idempotency_key="provider-two",
            provider_reference="SIM-PROVIDER-DUPLICATE",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_only_one_paid_payment_per_order(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-one-paid@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-PAID-ONE",
            idempotency_key="paid-one",
            status=PAYMENT_STATUS_PAID,
        )
    )
    db.session.commit()

    db.session.add(
        _payment(
            order,
            reference="PAY-PAID-TWO",
            idempotency_key="paid-two",
            status=PAYMENT_STATUS_PAID,
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    paid_count = db.session.scalar(
        select(Payment.id).where(
            Payment.order_id == order.id,
            Payment.status == PAYMENT_STATUS_PAID,
        )
    )
    assert paid_count is not None


def test_payment_status_and_amount_constraints(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-constraints@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-BAD-STATUS",
            idempotency_key="bad-status",
            status="bogus",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    db.session.add(
        _payment(
            order,
            reference="PAY-BAD-AMOUNT",
            idempotency_key="bad-amount",
            amount=Decimal("0.00"),
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_payment_currency_constraint(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-currency@example.com")
    order = make_order(user)

    db.session.add(
        _payment(
            order,
            reference="PAY-BAD-CURRENCY",
            idempotency_key="bad-currency",
            currency="US",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_order_with_payment_cannot_be_deleted(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-order-restrict@example.com")
    order = make_order(user)
    db.session.add(
        _payment(
            order,
            reference="PAY-RESTRICT",
            idempotency_key="restrict",
        )
    )
    db.session.commit()

    db.session.delete(order)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    assert db.session.get(Order, order.id) is not None
