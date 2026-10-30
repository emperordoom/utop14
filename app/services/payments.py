"""Payment attempt creation, expiry and simulated processing services."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Final

from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import Order, Payment, User
from app.models.order import ORDER_STATUS_CANCELLED, PAYMENT_STATUS_UNPAID
from app.models.payment import (
    PAYMENT_CURRENCY_IDR,
    PAYMENT_METHOD_SIMULATED,
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_EXPIRED,
    PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_PENDING,
)
from app.payments.providers.simulated import (
    SIMULATED_OUTCOME_FAILURE,
    SIMULATED_OUTCOME_SUCCESS,
    SIMULATED_OUTCOMES,
    SimulatedPaymentProvider,
)

PAYMENT_ELIGIBLE_ORDER_STATUSES: Final = frozenset({"pending", "processing"})
_CENT: Final = Decimal("0.01")
_DEFAULT_TTL_MINUTES: Final = 15


class PaymentError(Exception):
    """Base error for payment operations."""


class PaymentNotFound(PaymentError):
    """Raised when a payment is absent or not owned by the requesting user."""


class PaymentStateError(PaymentError):
    """Raised when an order/payment state does not permit the operation."""


class PaymentUnavailable(PaymentError):
    """Raised when the configured payment provider is unavailable."""


@dataclass(frozen=True, slots=True)
class PaymentProcessResult:
    """Outcome of a simulated processing request."""

    payment: Payment
    message: str
    category: str = "info"


def payment_provider_available() -> bool:
    """Whether the configured provider is available in this environment."""
    provider = str(current_app.config.get("PAYMENT_PROVIDER") or "").strip().lower()
    enabled = bool(current_app.config.get("PAYMENT_SIMULATION_ENABLED"))
    return provider == PAYMENT_PROVIDER_SIMULATED and enabled


def simulation_enabled() -> bool:
    """Whether the development-only simulation endpoint is enabled."""
    return payment_provider_available()


def payment_attempt_ttl_minutes() -> int:
    """Return the configured positive payment deadline in minutes.

    Only a genuine positive ``int`` is accepted.  Booleans (an ``int``
    subclass), floats, strings, ``None``, zero and negative values all fall
    back to the safe default instead of being coerced.
    """
    raw_value = current_app.config.get("PAYMENT_ATTEMPT_TTL_MINUTES", _DEFAULT_TTL_MINUTES)
    if type(raw_value) is not int or raw_value <= 0:
        return _DEFAULT_TTL_MINUTES
    return raw_value


def can_pay_order(order: Order) -> bool:
    """Whether an order is currently eligible for a new payment attempt."""
    return (
        order.status in PAYMENT_ELIGIBLE_ORDER_STATUSES
        and order.payment_status == PAYMENT_STATUS_UNPAID
        and order.total > 0
    )


def validate_payment_eligibility(order: Order) -> None:
    """Raise a clear payment error when an order cannot be paid."""
    if order.status == ORDER_STATUS_CANCELLED:
        raise PaymentStateError("This order is cancelled.")
    if order.status not in PAYMENT_ELIGIBLE_ORDER_STATUSES:
        raise PaymentStateError("Payment is only available for pending or processing orders.")
    if order.payment_status == PAYMENT_STATUS_PAID:
        raise PaymentStateError("This order is already paid.")
    if order.payment_status != PAYMENT_STATUS_UNPAID:
        raise PaymentStateError("This order is not eligible for payment.")
    if order.total <= 0:
        raise PaymentStateError("Order total must be positive before payment.")


def _normalize_order_number(order_number: str) -> str:
    return order_number.strip().upper()


def _lock_order_by_number(order_number: str) -> Order | None:
    normalized = _normalize_order_number(order_number)
    return db.session.scalar(
        select(Order).where(Order.order_number == normalized).with_for_update()
    )


def _lock_user_by_id(user_id: int) -> User | None:
    return db.session.scalar(select(User).where(User.id == user_id).with_for_update())


def _lock_order_by_id(order_id: int) -> Order | None:
    return db.session.scalar(select(Order).where(Order.id == order_id).with_for_update())


def _lock_payment(payment_reference: str) -> Payment | None:
    return db.session.scalar(
        select(Payment)
        .where(Payment.payment_reference == payment_reference.strip().upper())
        .with_for_update()
    )


def _validate_idempotency_key(value: str | None) -> str:
    if not isinstance(value, str):
        raise PaymentStateError("A valid idempotency key is required.")
    key = value.strip()
    if not key or len(key) > 64:
        raise PaymentStateError("A valid idempotency key is required.")
    return key


def _generate_payment_reference() -> str:
    """Allocate a non-sequential customer-facing payment reference."""
    for _ in range(5):
        candidate = f"PAY-{secrets.token_hex(8).upper()}"
        exists = db.session.scalar(select(Payment.id).where(Payment.payment_reference == candidate))
        if exists is None:
            return candidate
    raise PaymentStateError("Could not allocate a payment reference. Please try again.")


def _expire_locked_payment(payment: Payment, now: datetime) -> None:
    payment.status = PAYMENT_STATUS_EXPIRED
    payment.expired_at = now


def _fail_locked_payment(payment: Payment, now: datetime) -> None:
    payment.status = PAYMENT_STATUS_FAILED
    payment.failed_at = now


def create_payment_attempt(
    user_id: int,
    order_number: str,
    idempotency_key: str | None,
) -> Payment:
    """Create one pending payment attempt using the order's server-side total."""
    if not payment_provider_available():
        raise PaymentUnavailable("Payments are unavailable in this environment.")

    key = _validate_idempotency_key(idempotency_key)

    try:
        # Serialize all payment creation for one owner.  The user row lock is
        # held until commit/rollback, so two concurrent requests for different
        # orders cannot both pass the idempotency-key conflict check.  Lock
        # order is User -> Order -> Payment everywhere in this flow.
        user = _lock_user_by_id(user_id)
        if user is None:
            raise PaymentNotFound("Order not found.")

        order = _lock_order_by_number(order_number)
        if order is None or order.user_id != user_id:
            raise PaymentNotFound("Order not found.")

        existing = db.session.scalar(
            select(Payment)
            .where(
                Payment.order_id == order.id,
                Payment.idempotency_key == key,
            )
            .with_for_update()
        )
        if existing is not None:
            db.session.commit()
            return existing

        # An idempotency key is bound to the order it was first used with.  A
        # key from a different order must fail rather than silently creating a
        # second attempt.  The key is scoped to the authenticated owner.
        conflicting = db.session.scalar(
            select(Payment.id)
            .join(Payment.order)
            .where(
                Payment.idempotency_key == key,
                Payment.order_id != order.id,
                Order.user_id == user_id,
            )
            .with_for_update(of=Payment)
        )
        if conflicting is not None:
            raise PaymentStateError("This idempotency key has already been used for another order.")

        validate_payment_eligibility(order)

        amount = order.total.quantize(_CENT)
        now = datetime.now(UTC)
        provider = SimulatedPaymentProvider()

        payment = Payment(
            payment_reference=_generate_payment_reference(),
            order=order,
            provider=provider.name,
            payment_method=PAYMENT_METHOD_SIMULATED,
            amount=amount,
            currency=PAYMENT_CURRENCY_IDR,
            status=PAYMENT_STATUS_PENDING,
            idempotency_key=key,
            expires_at=now + timedelta(minutes=payment_attempt_ttl_minutes()),
        )
        db.session.add(payment)
        db.session.commit()
        return payment
    except PaymentError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        db.session.rollback()
        raise PaymentStateError("Could not create a payment attempt.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentStateError("Could not create a payment attempt.") from exc


def get_payment_for_user(user_id: int, payment_reference: str) -> Payment | None:
    """Return one payment attempt only when its order belongs to the user."""
    normalized = payment_reference.strip().upper()
    statement = (
        select(Payment)
        .join(Payment.order)
        .options(joinedload(Payment.order))
        .where(
            Payment.payment_reference == normalized,
            Order.user_id == user_id,
        )
    )
    return db.session.scalar(statement)


def list_payments_for_order(order_id: int) -> list[Payment]:
    """Return an order's payment attempts newest first."""
    statement = (
        select(Payment)
        .where(Payment.order_id == order_id)
        .order_by(Payment.created_at.desc(), Payment.id.desc())
    )
    return list(db.session.scalars(statement).all())


def expire_payment_attempt(
    payment_reference: str,
    *,
    now: datetime | None = None,
) -> Payment:
    """Expire a pending attempt once its deadline has passed.

    Attempts are never expired early; before ``expires_at`` this raises
    ``PaymentStateError`` and rolls back without changing state.  Already
    expired attempts are returned unchanged for idempotency.
    """
    now = now or datetime.now(UTC)
    try:
        order_id = db.session.scalar(
            select(Payment.order_id).where(
                Payment.payment_reference == payment_reference.strip().upper()
            )
        )
        if order_id is None:
            raise PaymentNotFound("Payment attempt not found.")

        order = _lock_order_by_id(order_id)
        payment = _lock_payment(payment_reference)
        if order is None or payment is None or payment.order_id != order.id:
            raise PaymentNotFound("Payment attempt not found.")

        if payment.status == PAYMENT_STATUS_EXPIRED:
            db.session.commit()
            return payment
        if payment.status != PAYMENT_STATUS_PENDING:
            raise PaymentStateError("Only pending payment attempts can expire.")

        # A pending attempt cannot be expired before its deadline.  Raising
        # rolls back the transaction so no false expiry is committed.
        if now < payment.expires_at:
            raise PaymentStateError("This payment attempt cannot be expired before its deadline.")

        _expire_locked_payment(payment, now)
        db.session.commit()
        return payment
    except PaymentError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentStateError("Payment attempt could not be expired.") from exc


def process_simulated_payment(
    user_id: int,
    payment_reference: str,
    outcome: str,
    *,
    now: datetime | None = None,
) -> PaymentProcessResult:
    """Process one development-only simulated payment outcome atomically."""
    if outcome not in SIMULATED_OUTCOMES:
        raise PaymentStateError("Choose a valid simulated payment outcome.")
    if not simulation_enabled():
        raise PaymentUnavailable("Simulated payments are disabled.")

    now = now or datetime.now(UTC)

    try:
        order_id = db.session.scalar(
            select(Payment.order_id).where(
                Payment.payment_reference == payment_reference.strip().upper()
            )
        )
        if order_id is None:
            raise PaymentNotFound("Payment attempt not found.")

        # Lock order first, matching cancellation and status transitions.
        order = _lock_order_by_id(order_id)
        payment = _lock_payment(payment_reference)
        if order is None or payment is None or payment.order_id != order.id:
            raise PaymentNotFound("Payment attempt not found.")
        if order.user_id != user_id:
            raise PaymentNotFound("Payment attempt not found.")
        if payment.provider != PAYMENT_PROVIDER_SIMULATED:
            raise PaymentStateError("Unsupported payment provider.")

        if payment.status == PAYMENT_STATUS_PAID:
            if outcome == SIMULATED_OUTCOME_SUCCESS:
                db.session.commit()
                return PaymentProcessResult(
                    payment,
                    "This payment is already paid. No further money moved.",
                    "info",
                )
            raise PaymentStateError("This payment is already paid.")

        if payment.status == PAYMENT_STATUS_FAILED:
            if outcome == SIMULATED_OUTCOME_FAILURE:
                db.session.commit()
                return PaymentProcessResult(
                    payment,
                    "This payment attempt has already failed.",
                    "info",
                )
            raise PaymentStateError("This payment attempt has already failed.")

        if payment.status == PAYMENT_STATUS_EXPIRED:
            db.session.commit()
            if order.status == ORDER_STATUS_CANCELLED:
                return PaymentProcessResult(
                    payment,
                    "This order is cancelled. The payment attempt expired without payment.",
                    "error",
                )
            if order.payment_status == PAYMENT_STATUS_PAID:
                return PaymentProcessResult(
                    payment,
                    "This order is already paid. The payment attempt expired.",
                    "error",
                )
            if order.status not in PAYMENT_ELIGIBLE_ORDER_STATUSES:
                return PaymentProcessResult(
                    payment,
                    "This order is no longer eligible for payment. The payment attempt expired.",
                    "error",
                )
            if order.payment_status != PAYMENT_STATUS_UNPAID:
                return PaymentProcessResult(
                    payment,
                    "This order is not eligible for payment. The payment attempt expired.",
                    "error",
                )
            return PaymentProcessResult(
                payment,
                "This payment attempt has expired. The order remains unpaid.",
                "error",
            )

        if payment.status != PAYMENT_STATUS_PENDING:
            raise PaymentStateError("This payment attempt cannot be processed.")

        if now >= payment.expires_at:
            _expire_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "This payment attempt has expired. The order remains unpaid.",
                "error",
            )

        if order.status == ORDER_STATUS_CANCELLED:
            _expire_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "This order is cancelled. The payment attempt was closed without payment.",
                "error",
            )

        if order.payment_status == PAYMENT_STATUS_PAID:
            _expire_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "This order is already paid. No second payment was recorded.",
                "error",
            )

        if order.status not in PAYMENT_ELIGIBLE_ORDER_STATUSES:
            _expire_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "Payment is only available for pending or processing orders. The attempt expired.",
                "error",
            )

        if order.payment_status != PAYMENT_STATUS_UNPAID:
            _expire_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "This order is not eligible for payment. The attempt expired.",
                "error",
            )

        expected_amount = order.total.quantize(_CENT)
        if payment.amount != expected_amount or payment.currency != PAYMENT_CURRENCY_IDR:
            _fail_locked_payment(payment, now)
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "Payment amount did not match the order. The attempt failed.",
                "error",
            )

        if outcome == SIMULATED_OUTCOME_SUCCESS:
            provider = SimulatedPaymentProvider()
            payment.status = PAYMENT_STATUS_PAID
            payment.paid_at = now
            payment.provider_reference = provider.provider_reference(payment.payment_reference)
            order.payment_status = PAYMENT_STATUS_PAID
            db.session.commit()
            return PaymentProcessResult(
                payment,
                "Simulated payment completed. No real money moved.",
                "success",
            )

        payment.status = PAYMENT_STATUS_FAILED
        payment.failed_at = now
        db.session.commit()
        return PaymentProcessResult(
            payment,
            "Simulated payment failed. The order remains unpaid.",
            "info",
        )
    except PaymentError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        db.session.rollback()
        raise PaymentStateError("Payment could not be processed.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentStateError("Payment could not be processed.") from exc
