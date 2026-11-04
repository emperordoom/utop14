"""PostgreSQL-backed tests for payment-proof constraints and history."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Order, Payment, PaymentProof, User
from app.models.payment_proof import (
    PAYMENT_PROOF_STATUS_APPROVED,
    PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    PAYMENT_PROOF_STATUS_REJECTED,
)
from app.services.payments import create_manual_payment_attempt


def _manual_payment(
    user: User,
    order: Order,
    *,
    key: str = "proof-model-key",
) -> Payment:
    return create_manual_payment_attempt(user.id, order.order_number, key)


def _proof(
    payment: Payment,
    *,
    filename: str = "a" * 32 + ".png",
    status: str = PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    file_size: int = 128,
    rejection_reason: str | None = None,
) -> PaymentProof:
    return PaymentProof(
        payment_id=payment.id,
        proof_filename=filename,
        mime_type="image/png",
        file_size=file_size,
        status=status,
        submitted_at=datetime.now(UTC),
        rejection_reason=rejection_reason,
    )


def test_proof_status_and_size_constraints(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="proof-model-constraints@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)

    db.session.add(_proof(payment, status="bogus"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    db.session.add(_proof(payment, file_size=0))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    db.session.add(_proof(payment, file_size=5 * 1024 * 1024 + 1))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_rejected_proof_requires_reason(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="proof-model-reason@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)

    db.session.add(
        _proof(
            payment,
            status=PAYMENT_PROOF_STATUS_REJECTED,
            rejection_reason=None,
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_only_one_pending_review_proof_per_payment(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="proof-model-pending@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)

    db.session.add(_proof(payment, filename="1" * 32 + ".png"))
    db.session.commit()

    db.session.add(_proof(payment, filename="2" * 32 + ".png"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_only_one_approved_proof_per_payment(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="proof-model-approved@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)

    db.session.add(
        _proof(
            payment,
            filename="3" * 32 + ".png",
            status=PAYMENT_PROOF_STATUS_APPROVED,
        )
    )
    db.session.commit()

    db.session.add(
        _proof(
            payment,
            filename="4" * 32 + ".png",
            status=PAYMENT_PROOF_STATUS_APPROVED,
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_proof_filename_is_unique(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="proof-model-filename@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    filename = "5" * 32 + ".pdf"

    db.session.add(_proof(payment, filename=filename))
    db.session.commit()

    db.session.add(
        _proof(
            payment,
            filename=filename,
            status=PAYMENT_PROOF_STATUS_REJECTED,
            rejection_reason="Duplicate filename",
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
