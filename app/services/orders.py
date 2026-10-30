"""Order history, cancellation and staff lifecycle services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import Order, OrderItem, Payment, ProductVariant
from app.models.order import (
    ORDER_STATUS_CANCELLED,
    ORDER_STATUS_PENDING,
    ORDER_STATUSES,
    PAYMENT_STATUS_UNPAID,
    PAYMENT_STATUSES,
)
from app.models.payment import PAYMENT_STATUS_EXPIRED, PAYMENT_STATUS_PENDING

STAFF_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "pending": frozenset({"processing", "cancelled"}),
    "processing": frozenset({"shipped", "cancelled"}),
    "shipped": frozenset({"delivered"}),
    "delivered": frozenset(),
    "cancelled": frozenset(),
}


class OrderError(Exception):
    """Base error for order lifecycle operations."""


class OrderNotFound(OrderError):
    """Raised when an order is absent or not owned by the requesting user."""


class OrderStateError(OrderError):
    """Raised when an order transition is not allowed or cannot be completed."""


def _normalize_order_number(order_number: str) -> str:
    return order_number.strip().upper()


def _lock_order(order_number: str) -> Order | None:
    """Lock one order by number for a lifecycle transaction."""
    normalized = _normalize_order_number(order_number)
    return db.session.scalar(
        select(Order).where(Order.order_number == normalized).with_for_update()
    )


def _restore_variant_stock(variant_id: int, quantity: int) -> bool:
    """Restore stock only when the original variant record still exists."""
    if quantity <= 0:
        return False

    variant = db.session.scalar(
        select(ProductVariant).where(ProductVariant.id == variant_id).with_for_update()
    )
    if variant is None:
        # A deleted variant has no row to restore.  Never fall back to SKU or
        # any other variant.
        return True

    variant.stock += quantity
    return True


def _cancel_locked_order(order: Order, *, actor_user_id: int, reason: str | None) -> None:
    """Restore stock and mark an already-locked order as cancelled."""
    items = list(
        db.session.scalars(
            select(OrderItem)
            .where(OrderItem.order_id == order.id)
            .order_by(OrderItem.variant_id, OrderItem.id)
        )
    )
    for item in items:
        if item.variant_id is not None and not _restore_variant_stock(
            item.variant_id, item.quantity
        ):
            raise OrderStateError("Order could not be cancelled safely. No changes were saved.")

    now = datetime.now(UTC)
    pending_payments = db.session.scalars(
        select(Payment)
        .where(
            Payment.order_id == order.id,
            Payment.status == PAYMENT_STATUS_PENDING,
        )
        .with_for_update()
    ).all()
    for payment in pending_payments:
        payment.status = PAYMENT_STATUS_EXPIRED
        payment.expired_at = now

    cleaned_reason = (reason or "").strip()
    order.status = ORDER_STATUS_CANCELLED
    order.cancelled_at = now
    order.cancelled_by_user_id = actor_user_id
    order.cancellation_reason = cleaned_reason[:500] or None


def customer_can_cancel(order: Order) -> bool:
    """Whether a customer is allowed to cancel this order."""
    return order.status == ORDER_STATUS_PENDING and order.payment_status == PAYMENT_STATUS_UNPAID


def cancel_customer_order(
    user_id: int,
    order_number: str,
    reason: str | None = None,
) -> Order:
    """Cancel a customer's pending unpaid order and restore stock atomically."""
    try:
        order = _lock_order(order_number)
        if order is None or order.user_id != user_id:
            raise OrderNotFound("Order not found.")
        if order.status == ORDER_STATUS_CANCELLED:
            raise OrderStateError("This order is already cancelled.")
        if not customer_can_cancel(order):
            raise OrderStateError("Only pending unpaid orders can be cancelled.")

        _cancel_locked_order(order, actor_user_id=user_id, reason=reason)
        db.session.commit()
        return order
    except OrderError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise OrderStateError("Order could not be cancelled. Please try again.") from exc


def allowed_staff_transitions(order: Order) -> tuple[str, ...]:
    """Return the statuses staff may move this order to, in display order."""
    allowed = set(STAFF_TRANSITIONS.get(order.status, frozenset()))
    if order.payment_status != PAYMENT_STATUS_UNPAID:
        allowed.discard(ORDER_STATUS_CANCELLED)
    return tuple(status for status in ORDER_STATUSES if status in allowed)


def transition_staff_order(
    order_number: str,
    new_status: str,
    *,
    actor_user_id: int,
    reason: str | None = None,
) -> Order:
    """Apply one validated staff status transition under an order row lock."""
    if new_status not in ORDER_STATUSES:
        raise OrderStateError("Choose a valid order status.")

    try:
        order = _lock_order(order_number)
        if order is None:
            raise OrderNotFound("Order not found.")

        allowed = set(STAFF_TRANSITIONS.get(order.status, frozenset()))
        if order.payment_status != PAYMENT_STATUS_UNPAID:
            allowed.discard(ORDER_STATUS_CANCELLED)

        if new_status not in allowed:
            if order.status == ORDER_STATUS_CANCELLED:
                raise OrderStateError("This order is already cancelled.")
            if order.status == "delivered":
                raise OrderStateError("Delivered orders are final.")
            if new_status == ORDER_STATUS_CANCELLED:
                if order.payment_status != PAYMENT_STATUS_UNPAID:
                    raise OrderStateError(
                        "Paid orders require a refund workflow before cancellation."
                    )
                raise OrderStateError(f"Cannot cancel an order with status {order.status}.")
            raise OrderStateError(f"Cannot change order from {order.status} to {new_status}.")

        if new_status == ORDER_STATUS_CANCELLED:
            _cancel_locked_order(
                order,
                actor_user_id=actor_user_id,
                reason=reason,
            )
        else:
            order.status = new_status

        db.session.commit()
        return order
    except OrderError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise OrderStateError("Order status could not be updated. Please try again.") from exc


def list_customer_orders(user_id: int, *, page: int = 1, per_page: int = 10):
    """Return a paginated newest-first history for one customer."""
    statement = (
        select(Order)
        .where(Order.user_id == user_id)
        .order_by(Order.created_at.desc(), Order.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


@dataclass(frozen=True, slots=True)
class StaffOrderFilters:
    """Normalized operator/admin order-list filters."""

    status: str | None = None
    payment_status: str | None = None
    query: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        status: str | None = None,
        payment_status: str | None = None,
        q: str | None = None,
    ) -> StaffOrderFilters:
        normalized_status = status.strip() if status else None
        if normalized_status not in ORDER_STATUSES:
            normalized_status = None

        normalized_payment = payment_status.strip() if payment_status else None
        if normalized_payment not in PAYMENT_STATUSES:
            normalized_payment = None

        normalized_query = q.strip()[:80] if q and q.strip() else None
        return cls(
            status=normalized_status,
            payment_status=normalized_payment,
            query=normalized_query,
        )

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {
            "status": self.status,
            "payment_status": self.payment_status,
            "q": self.query,
        }
        return {key: value for key, value in values.items() if value}


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_staff_orders(
    filters: StaffOrderFilters,
    *,
    page: int = 1,
    per_page: int = 20,
):
    """Return a paginated, filtered order list for operators and admins."""
    conditions = []
    if filters.status is not None:
        conditions.append(Order.status == filters.status)
    if filters.payment_status is not None:
        conditions.append(Order.payment_status == filters.payment_status)
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(Order.order_number.ilike(pattern, escape="\\"))

    statement = (
        select(Order)
        .options(joinedload(Order.user))
        .where(*conditions)
        .order_by(Order.created_at.desc(), Order.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_staff_order(order_number: str) -> Order | None:
    """Return one order with customer, actor and item snapshots for staff."""
    normalized = _normalize_order_number(order_number)
    statement = (
        select(Order)
        .options(
            joinedload(Order.user),
            joinedload(Order.cancelled_by),
            selectinload(Order.items),
            selectinload(Order.payments),
        )
        .where(Order.order_number == normalized)
    )
    return db.session.scalar(statement)
