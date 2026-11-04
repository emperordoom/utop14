"""Manual bank-transfer payment proof and review history model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.payment import Payment
    from app.models.user import User

PAYMENT_PROOF_STATUS_PENDING_REVIEW: Final = "pending_review"
PAYMENT_PROOF_STATUS_APPROVED: Final = "approved"
PAYMENT_PROOF_STATUS_REJECTED: Final = "rejected"
PAYMENT_PROOF_STATUS_CANCELLED: Final = "cancelled"

PAYMENT_PROOF_STATUSES: Final[tuple[str, ...]] = (
    PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    PAYMENT_PROOF_STATUS_APPROVED,
    PAYMENT_PROOF_STATUS_REJECTED,
    PAYMENT_PROOF_STATUS_CANCELLED,
)

PAYMENT_PROOF_MAX_BYTES: Final = 5 * 1024 * 1024


class PaymentProof(TimestampMixin, Base):
    """One uploaded transfer proof with preserved review history."""

    __tablename__ = "payment_proofs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'cancelled')",
            name="payment_proof_status_valid",
        ),
        CheckConstraint("file_size > 0", name="payment_proof_file_size_positive"),
        CheckConstraint(
            f"file_size <= {PAYMENT_PROOF_MAX_BYTES}",
            name="payment_proof_file_size_limit",
        ),
        CheckConstraint(
            "status <> 'rejected' OR rejection_reason IS NOT NULL",
            name="payment_proof_rejection_reason_present",
        ),
        Index(
            "ix_payment_proofs_payment_id_submitted_at",
            "payment_id",
            "submitted_at",
        ),
        Index("ix_payment_proofs_status", "status"),
        Index(
            "uq_payment_proofs_one_pending_per_payment",
            "payment_id",
            unique=True,
            postgresql_where=text("status = 'pending_review'"),
        ),
        Index(
            "uq_payment_proofs_one_approved_per_payment",
            "payment_id",
            unique=True,
            postgresql_where=text("status = 'approved'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    payment_id: Mapped[int] = mapped_column(
        ForeignKey("payments.id", ondelete="RESTRICT"),
        nullable=False,
    )
    proof_filename: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=PAYMENT_PROOF_STATUS_PENDING_REVIEW,
        server_default=text("'pending_review'"),
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    payment: Mapped[Payment] = relationship(back_populates="proofs")
    reviewed_by: Mapped[User | None] = relationship(foreign_keys=[reviewed_by_user_id])

    def __repr__(self) -> str:
        return (
            f"<PaymentProof id={self.id!r} payment_id={self.payment_id!r} status={self.status!r}>"
        )
