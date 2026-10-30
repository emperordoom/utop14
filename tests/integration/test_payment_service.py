"""PostgreSQL-backed tests for payment creation and simulated processing."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import func, select

from app.extensions import db
from app.models import Order, OrderItem, Payment, ProductVariant, User
from app.models.payment import (
    PAYMENT_CURRENCY_IDR,
    PAYMENT_METHOD_SIMULATED,
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_EXPIRED,
    PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_PENDING,
    PAYMENT_STATUS_REFUNDED,
)
from app.services.orders import cancel_customer_order
from app.services.payments import (
    PaymentNotFound,
    PaymentStateError,
    PaymentUnavailable,
    create_payment_attempt,
    expire_payment_attempt,
    get_payment_for_user,
    process_simulated_payment,
)


def _reload_payment(payment: Payment) -> Payment:
    db.session.expire_all()
    refreshed = db.session.get(Payment, payment.id)
    assert refreshed is not None
    return refreshed


def _reload_order(order: Order) -> Order:
    db.session.expire_all()
    refreshed = db.session.get(Order, order.id)
    assert refreshed is not None
    return refreshed


def test_create_payment_attempt_uses_order_amount_and_idr(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-create@example.com")
    order = make_order(user, sku="UT014-VT-WBK-M", quantity=1)
    before = datetime.now(UTC)

    payment = create_payment_attempt(user.id, order.order_number, "create-key-123456")

    assert payment.payment_reference.startswith("PAY-")
    assert payment.amount == order.total
    assert payment.currency == PAYMENT_CURRENCY_IDR
    assert payment.status == PAYMENT_STATUS_PENDING
    assert payment.provider == PAYMENT_PROVIDER_SIMULATED
    assert payment.payment_method == PAYMENT_METHOD_SIMULATED
    assert payment.provider_reference is None
    assert before + timedelta(minutes=14, seconds=59) <= payment.expires_at
    assert payment.expires_at <= datetime.now(UTC) + timedelta(minutes=15, seconds=2)


def test_duplicate_initiation_returns_same_attempt(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-duplicate@example.com")
    order = make_order(user)

    first = create_payment_attempt(user.id, order.order_number, "duplicate-key-123")
    second = create_payment_attempt(user.id, order.order_number, "duplicate-key-123")

    assert first.id == second.id
    assert db.session.scalar(select(func.count(Payment.id))) == 1


def test_payment_creation_rejects_another_users_order(
    app: Flask,
    make_user,
    make_order,
) -> None:
    owner: User = make_user(email="payment-owner-service@example.com")
    other: User = make_user(email="payment-other-service@example.com")
    order = make_order(owner)

    with pytest.raises(PaymentNotFound):
        create_payment_attempt(other.id, order.order_number, "cross-user-key-123")


@pytest.mark.parametrize(
    ("status", "payment_status"),
    [
        ("shipped", "unpaid"),
        ("delivered", "unpaid"),
        ("cancelled", "unpaid"),
        ("pending", "paid"),
        ("pending", "failed"),
        ("pending", "refunded"),
    ],
)
def test_payment_creation_rejects_ineligible_orders(
    app: Flask,
    make_user,
    make_order,
    status: str,
    payment_status: str,
) -> None:
    user: User = make_user(email=f"payment-ineligible-{status}-{payment_status}@example.com")
    order = make_order(user, status=status, payment_status=payment_status)

    with pytest.raises(PaymentStateError):
        create_payment_attempt(user.id, order.order_number, "ineligible-key-123")


def test_successful_payment_marks_order_paid_idempotently(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-success-service@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "success-key-123")

    processed = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "success",
    )

    assert processed.payment.status == PAYMENT_STATUS_PAID
    assert processed.payment.paid_at is not None
    assert processed.payment.provider_reference is not None
    assert processed.payment.provider_reference.startswith("SIM-")
    refreshed_order = _reload_order(order)
    assert refreshed_order.payment_status == PAYMENT_STATUS_PAID

    repeated = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "success",
    )
    assert repeated.payment.id == payment.id
    assert repeated.payment.status == PAYMENT_STATUS_PAID
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(Payment.status == PAYMENT_STATUS_PAID)
        )
        == 1
    )


def test_failed_payment_leaves_order_unpaid(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-failure-service@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "failure-key-123")

    processed = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "failure",
    )

    assert processed.payment.status == PAYMENT_STATUS_FAILED
    assert processed.payment.failed_at is not None
    assert _reload_order(order).payment_status == "unpaid"

    repeated = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "failure",
    )
    assert repeated.payment.id == payment.id


def test_expired_payment_cannot_become_paid(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expiry-service@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expiry-key-123")

    payment.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.session.commit()

    result = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "success",
    )

    assert result.payment.status == PAYMENT_STATUS_EXPIRED
    assert "expired" in result.message.lower()
    refreshed = _reload_payment(payment)
    assert refreshed.status == PAYMENT_STATUS_EXPIRED
    assert refreshed.expired_at is not None
    assert _reload_order(order).payment_status == "unpaid"


def test_expire_payment_attempt_is_idempotent(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expire-function@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expire-key-123")
    after_deadline = payment.expires_at + timedelta(seconds=1)

    expired = expire_payment_attempt(payment.payment_reference, now=after_deadline)
    repeated = expire_payment_attempt(payment.payment_reference, now=after_deadline)

    assert expired.status == PAYMENT_STATUS_EXPIRED
    assert repeated.id == expired.id
    assert repeated.status == PAYMENT_STATUS_EXPIRED
    assert _reload_order(order).payment_status == "unpaid"


def test_expire_payment_attempt_before_deadline_keeps_pending(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expire-early@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expire-early-key")
    before_deadline = payment.expires_at - timedelta(seconds=1)

    with pytest.raises(PaymentStateError, match="deadline"):
        expire_payment_attempt(payment.payment_reference, now=before_deadline)

    refreshed = _reload_payment(payment)
    assert refreshed.status == PAYMENT_STATUS_PENDING
    assert refreshed.expired_at is None
    assert _reload_order(order).payment_status == "unpaid"


def test_expire_payment_attempt_at_deadline_expires(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expire-at-deadline@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expire-at-deadline-key")

    expired = expire_payment_attempt(
        payment.payment_reference,
        now=payment.expires_at,
    )

    assert expired.status == PAYMENT_STATUS_EXPIRED
    refreshed = _reload_payment(payment)
    assert refreshed.status == PAYMENT_STATUS_EXPIRED
    assert refreshed.expired_at is not None
    assert _reload_order(order).payment_status == "unpaid"


def test_expire_payment_attempt_after_deadline_expires(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expire-after-deadline@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expire-after-deadline-key")
    after_deadline = payment.expires_at + timedelta(minutes=1)

    expired = expire_payment_attempt(payment.payment_reference, now=after_deadline)

    assert expired.status == PAYMENT_STATUS_EXPIRED
    assert _reload_payment(payment).expired_at is not None


def test_expired_attempt_cannot_be_paid(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-expired-cannot-pay@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "expired-cannot-pay-key")
    expire_payment_attempt(
        payment.payment_reference,
        now=payment.expires_at + timedelta(seconds=1),
    )

    result = process_simulated_payment(
        user.id,
        payment.payment_reference,
        "success",
    )

    assert result.payment.status == PAYMENT_STATUS_EXPIRED
    assert "expired" in result.message.lower()
    assert _reload_order(order).payment_status == "unpaid"


@pytest.mark.parametrize(
    ("initial_status", "outcome"),
    [
        (PAYMENT_STATUS_PAID, "failure"),
        (PAYMENT_STATUS_FAILED, "success"),
        (PAYMENT_STATUS_REFUNDED, "success"),
    ],
)
def test_invalid_payment_transitions_are_rejected(
    app: Flask,
    make_user,
    make_order,
    initial_status: str,
    outcome: str,
) -> None:
    user: User = make_user(email=f"payment-transition-{initial_status}@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "transition-key-123")
    payment.status = initial_status
    if initial_status == PAYMENT_STATUS_PAID:
        payment.paid_at = datetime.now(UTC)
    if initial_status == PAYMENT_STATUS_FAILED:
        payment.failed_at = datetime.now(UTC)
    if initial_status == PAYMENT_STATUS_EXPIRED:
        payment.expired_at = datetime.now(UTC)
    if initial_status == PAYMENT_STATUS_REFUNDED:
        payment.refunded_at = datetime.now(UTC)
    db.session.commit()

    with pytest.raises(PaymentStateError):
        process_simulated_payment(
            user.id,
            payment.payment_reference,
            outcome,
        )


def test_multiple_attempts_allow_only_one_paid_payment(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-multiple-attempts@example.com")
    order = make_order(user)
    first = create_payment_attempt(user.id, order.order_number, "attempt-one-key-123")
    second = create_payment_attempt(user.id, order.order_number, "attempt-two-key-123")

    process_simulated_payment(user.id, first.payment_reference, "success")
    second_result = process_simulated_payment(user.id, second.payment_reference, "success")

    assert second_result.payment.status == PAYMENT_STATUS_EXPIRED
    assert "already paid" in second_result.message.lower()
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )
    assert _reload_payment(second).status == PAYMENT_STATUS_EXPIRED
    assert _reload_order(order).payment_status == PAYMENT_STATUS_PAID


def test_payment_amount_mismatch_does_not_mark_order_paid(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-amount-mismatch@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "amount-key-123")
    payment.amount = Decimal("1.00")
    db.session.commit()

    result = process_simulated_payment(user.id, payment.payment_reference, "success")

    assert result.payment.status == PAYMENT_STATUS_FAILED
    assert "amount" in result.message.lower()
    assert _reload_payment(payment).status == PAYMENT_STATUS_FAILED
    assert _reload_order(order).payment_status == "unpaid"


def test_payment_provider_unavailable_blocks_creation_and_processing(
    app: Flask,
    make_user,
    make_order,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user: User = make_user(email="payment-unavailable@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "available-key-123")

    monkeypatch.setitem(app.config, "PAYMENT_PROVIDER", "")
    monkeypatch.setitem(app.config, "PAYMENT_SIMULATION_ENABLED", False)

    with pytest.raises(PaymentUnavailable):
        create_payment_attempt(user.id, order.order_number, "unavailable-key-123")
    with pytest.raises(PaymentUnavailable):
        process_simulated_payment(user.id, payment.payment_reference, "success")


def test_payment_retrieval_is_owner_only(
    app: Flask,
    make_user,
    make_order,
) -> None:
    owner: User = make_user(email="payment-retrieve-owner@example.com")
    other: User = make_user(email="payment-retrieve-other@example.com")
    order = make_order(owner)
    payment = create_payment_attempt(owner.id, order.order_number, "retrieve-key-123")

    assert get_payment_for_user(owner.id, payment.payment_reference) is not None
    assert get_payment_for_user(other.id, payment.payment_reference) is None


def test_duplicate_key_returns_failed_attempt(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-idem-failed@example.com")
    order = make_order(user)
    first = create_payment_attempt(user.id, order.order_number, "failed-reuse-key")
    process_simulated_payment(user.id, first.payment_reference, "failure")

    reused = create_payment_attempt(user.id, order.order_number, "failed-reuse-key")

    assert reused.id == first.id
    assert reused.status == PAYMENT_STATUS_FAILED
    assert db.session.scalar(select(func.count(Payment.id))) == 1


def test_duplicate_key_returns_expired_attempt(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-idem-expired@example.com")
    order = make_order(user)
    first = create_payment_attempt(user.id, order.order_number, "expired-reuse-key")
    expire_payment_attempt(
        first.payment_reference,
        now=first.expires_at + timedelta(seconds=1),
    )

    reused = create_payment_attempt(user.id, order.order_number, "expired-reuse-key")

    assert reused.id == first.id
    assert reused.status == PAYMENT_STATUS_EXPIRED
    assert db.session.scalar(select(func.count(Payment.id))) == 1


def test_idempotency_key_cannot_be_reused_for_another_order(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-idem-cross-order@example.com")
    first_order = make_order(user)
    second_order = make_order(user)
    first = create_payment_attempt(
        user.id,
        first_order.order_number,
        "cross-order-key",
    )

    with pytest.raises(PaymentStateError, match="another order"):
        create_payment_attempt(
            user.id,
            second_order.order_number,
            "cross-order-key",
        )

    assert db.session.scalar(select(func.count(Payment.id))) == 1
    assert db.session.scalar(select(Payment.id).where(Payment.order_id == second_order.id)) is None
    assert _reload_payment(first).id == first.id


def test_new_key_after_failed_attempt_creates_new_attempt(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-new-key-after-failed@example.com")
    order = make_order(user)
    first = create_payment_attempt(user.id, order.order_number, "failed-first-key")
    process_simulated_payment(user.id, first.payment_reference, "failure")

    second = create_payment_attempt(user.id, order.order_number, "failed-second-key")

    assert second.id != first.id
    assert second.status == PAYMENT_STATUS_PENDING
    assert db.session.scalar(select(func.count(Payment.id))) == 2


def test_cancellation_expires_pending_payment_and_prevents_late_success(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-cancel-integration@example.com")
    order = make_order(user, quantity=1)
    payment = create_payment_attempt(user.id, order.order_number, "cancel-key-123")
    variant_id = db.session.scalar(
        select(OrderItem.variant_id).where(OrderItem.order_id == order.id).limit(1)
    )
    assert variant_id is not None
    stock_before_cancel = db.session.get(ProductVariant, variant_id).stock
    # The payment deadline is still in the future; cancellation must expire it
    # immediately anyway, in the same transaction as stock restoration.
    assert payment.expires_at > datetime.now(UTC)

    cancelled = cancel_customer_order(user.id, order.order_number, reason="Payment test")
    expired = _reload_payment(payment)

    assert cancelled.status == "cancelled"
    assert expired.status == PAYMENT_STATUS_EXPIRED
    assert expired.expired_at is not None
    assert _reload_order(order).payment_status == "unpaid"
    assert db.session.get(ProductVariant, variant_id).stock == stock_before_cancel + 1

    late_result = process_simulated_payment(user.id, payment.payment_reference, "success")

    assert late_result.payment.status == PAYMENT_STATUS_EXPIRED
    assert "cancelled" in late_result.message.lower()
    assert _reload_order(order).payment_status == "unpaid"
    assert db.session.get(ProductVariant, variant_id).stock == stock_before_cancel + 1


def test_concurrent_processing_of_same_payment_is_safe(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-concurrent-process@example.com")
    order = make_order(user)
    payment = create_payment_attempt(user.id, order.order_number, "concurrent-process-key")
    user_id = user.id
    order_id = order.id
    payment_reference = payment.payment_reference
    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[str] = []

    def attempt() -> None:
        with app.app_context():
            barrier.wait()
            try:
                processed = process_simulated_payment(
                    user_id,
                    payment_reference,
                    "success",
                )
                results.append(processed.payment.status)
            except Exception as exc:  # pragma: no cover - diagnostic safety
                errors.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert results == [PAYMENT_STATUS_PAID, PAYMENT_STATUS_PAID]
    db.session.expire_all()
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order_id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )
    assert db.session.get(Order, order_id).payment_status == PAYMENT_STATUS_PAID


def test_concurrent_initiation_with_same_key_creates_one_payment(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user: User = make_user(email="payment-concurrent-init@example.com")
    order = make_order(user)
    user_id = user.id
    order_id = order.id
    order_number = order.order_number
    barrier = threading.Barrier(2)
    references: list[str] = []
    errors: list[str] = []

    def attempt() -> None:
        with app.app_context():
            barrier.wait()
            try:
                payment = create_payment_attempt(
                    user_id,
                    order_number,
                    "concurrent-init-key-123",
                )
                references.append(payment.payment_reference)
            except Exception as exc:  # pragma: no cover - diagnostic safety
                errors.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert len(references) == 2
    assert references[0] == references[1]
    assert (
        db.session.scalar(select(func.count(Payment.id)).where(Payment.order_id == order_id)) == 1
    )


def test_concurrent_same_key_on_different_orders_creates_one_payment(
    app: Flask,
    make_user,
    make_order,
) -> None:
    """Two parallel transactions must not reuse one key across two orders."""
    user: User = make_user(email="payment-concurrent-cross-order@example.com")
    first_order = make_order(user)
    second_order = make_order(user)
    user_id = user.id
    order_numbers = (first_order.order_number, second_order.order_number)
    barrier = threading.Barrier(2)
    successes: list[tuple[int, str]] = []
    failures: list[str] = []

    def attempt(order_number: str) -> None:
        with app.app_context():
            barrier.wait()
            try:
                payment = create_payment_attempt(
                    user_id,
                    order_number,
                    "concurrent-cross-order-key",
                )
                successes.append((payment.order_id, payment.payment_reference))
            except PaymentStateError as exc:
                failures.append(str(exc))
            except Exception as exc:  # pragma: no cover - diagnostic safety
                failures.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=attempt, args=(number,)) for number in order_numbers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not any(thread.is_alive() for thread in threads)
    assert len(successes) == 1
    assert len(failures) == 1
    assert "another order" in failures[0]

    db.session.expire_all()
    assert db.session.scalar(select(func.count(Payment.id))) == 1
    winning_order_id, winning_reference = successes[0]
    assert winning_order_id in {first_order.id, second_order.id}
    assert (
        db.session.scalar(
            select(Payment.payment_reference).where(Payment.order_id == winning_order_id)
        )
        == winning_reference
    )
    other_order_id = second_order.id if winning_order_id == first_order.id else first_order.id
    assert (
        db.session.scalar(select(func.count(Payment.id)).where(Payment.order_id == other_order_id))
        == 0
    )
