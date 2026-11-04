"""Order payment attempt model."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.order import Order
    from app.models.payment_proof import PaymentProof

PAYMENT_STATUS_PENDING: Final = "pending"
PAYMENT_STATUS_PAID: Final = "paid"
PAYMENT_STATUS_FAILED: Final = "failed"
PAYMENT_STATUS_EXPIRED: Final = "expired"
PAYMENT_STATUS_REFUNDED: Final = "refunded"

PAYMENT_STATUSES: Final[tuple[str, ...]] = (
    PAYMENT_STATUS_PENDING,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_EXPIRED,
    PAYMENT_STATUS_REFUNDED,
)

PAYMENT_CURRENCY_IDR: Final = "IDR"
PAYMENT_PROVIDER_SIMULATED: Final = "simulated"
PAYMENT_METHOD_SIMULATED: Final = "simulated"
PAYMENT_PROVIDER_MANUAL_TRANSFER: Final = "manual_transfer"
PAYMENT_METHOD_BANK_TRANSFER: Final = "bank_transfer"


class Payment(TimestampMixin, Base):
    """One payment attempt belonging to an order."""

    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'paid', 'failed', 'expired', 'refunded')",
            name="payment_attempt_status_valid",
        ),
        CheckConstraint("amount > 0", name="payment_amount_positive"),
        CheckConstraint("char_length(currency) = 3", name="payment_currency_length"),
        UniqueConstraint(
            "order_id",
            "idempotency_key",
            name="payment_order_idempotency",
        ),
        UniqueConstraint(
            "provider",
            "provider_reference",
            name="payment_provider_reference",
        ),
        Index("ix_payments_order_id_created_at", "order_id", "created_at"),
        Index("ix_payments_status", "status"),
        Index(
            "uq_payments_one_paid_per_order",
            "order_id",
            unique=True,
            postgresql_where=text("status = 'paid'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    payment_reference: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        unique=True,
    )
    order_id: Mapped[int] = mapped_column(
        ForeignKey("orders.id", ondelete="RESTRICT"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=PAYMENT_PROVIDER_SIMULATED,
        server_default=text("'simulated'"),
    )
    payment_method: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=PAYMENT_METHOD_SIMULATED,
        server_default=text("'simulated'"),
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
        default=PAYMENT_CURRENCY_IDR,
        server_default=text("'IDR'"),
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=PAYMENT_STATUS_PENDING,
        server_default=text("'pending'"),
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    refunded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    order: Mapped[Order] = relationship(back_populates="payments")
    proofs: Mapped[list[PaymentProof]] = relationship(
        back_populates="payment",
        passive_deletes=True,
        order_by="PaymentProof.id.desc()",
    )

    def __repr__(self) -> str:
        return f"<Payment {self.payment_reference!r} status={self.status!r}>"
