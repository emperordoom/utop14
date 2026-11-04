"""Manual-transfer proof upload, review and transactional approval services."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import Order, Payment, PaymentProof, User
from app.models.order import ORDER_STATUS_CANCELLED, PAYMENT_STATUS_UNPAID
from app.models.payment import (
    PAYMENT_CURRENCY_IDR,
    PAYMENT_PROVIDER_MANUAL_TRANSFER,
    PAYMENT_STATUS_EXPIRED,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_PENDING,
)
from app.models.payment_proof import (
    PAYMENT_PROOF_STATUS_APPROVED,
    PAYMENT_PROOF_STATUS_CANCELLED,
    PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    PAYMENT_PROOF_STATUS_REJECTED,
    PAYMENT_PROOF_STATUSES,
)
from app.services.payments import PAYMENT_ELIGIBLE_ORDER_STATUSES
from app.services.proof_storage import (
    PreparedProof,
    ProofStorageError,
    ProofValidationError,
    delete_proof_file,
    prepare_proof_upload,
    store_proof_file,
)

_CENT: Final = Decimal("0.01")
_MAX_FILTER_LENGTH: Final = 80
_MAX_REJECTION_REASON: Final = 500


class PaymentProofError(Exception):
    """Base error for payment-proof operations."""


class PaymentProofNotFound(PaymentProofError):
    """Raised when a proof, payment or order cannot be found for its owner."""


class PaymentProofStateError(PaymentProofError):
    """Raised when the current payment/order/proof state blocks the action."""


class PaymentProofValidationError(PaymentProofError):
    """Raised when uploaded evidence or review input fails validation."""


@dataclass(frozen=True, slots=True)
class AdminProofFilters:
    """Normalized admin proof-list filters."""

    status: str | None = PAYMENT_PROOF_STATUS_PENDING_REVIEW
    query: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        status: str | None = None,
        q: str | None = None,
    ) -> AdminProofFilters:
        """Build filters from untrusted query-string values."""
        normalized_status = status.strip().lower() if isinstance(status, str) else None
        if normalized_status == "all":
            normalized_status = None
        elif normalized_status not in PAYMENT_PROOF_STATUSES:
            normalized_status = PAYMENT_PROOF_STATUS_PENDING_REVIEW

        normalized_query = q.strip()[:_MAX_FILTER_LENGTH] if isinstance(q, str) else None
        return cls(
            status=normalized_status,
            query=normalized_query or None,
        )

    def as_query_params(self) -> dict[str, str]:
        """Return filters for pagination links, preserving the all-status view."""
        values = {
            "status": self.status or "all",
            "q": self.query,
        }
        return {key: value for key, value in values.items() if value}


@dataclass(frozen=True, slots=True)
class ProofReviewResult:
    """Outcome of one admin proof review action."""

    proof: PaymentProof
    message: str
    category: str = "success"


def upload_payment_proof(
    user_id: int,
    payment_reference: str,
    upload: object,
    *,
    now: datetime | None = None,
) -> PaymentProof:
    """Validate ownership, deadline and evidence before creating a proof row."""
    now = now or datetime.now(UTC)
    prepared: PreparedProof | None = None

    try:
        order, payment = _lock_payment_context_by_reference(payment_reference)
        if order.user_id != user_id:
            raise PaymentProofNotFound("Payment proof not found.")
        if payment.provider != PAYMENT_PROVIDER_MANUAL_TRANSFER:
            raise PaymentProofStateError("This payment does not accept transfer proofs.")
        if payment.status == PAYMENT_STATUS_EXPIRED:
            raise PaymentProofStateError("This payment attempt has expired.")
        if payment.status != PAYMENT_STATUS_PENDING:
            raise PaymentProofStateError("Only pending payment attempts accept proofs.")
        if now >= payment.expires_at:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This payment attempt has expired.")
        if order.status == ORDER_STATUS_CANCELLED:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This order is cancelled.")
        if order.payment_status == PAYMENT_STATUS_PAID:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This order is already paid.")
        if order.status not in PAYMENT_ELIGIBLE_ORDER_STATUSES:
            raise PaymentProofStateError("This order is not eligible for payment.")
        if order.payment_status != PAYMENT_STATUS_UNPAID:
            raise PaymentProofStateError("This order is not eligible for payment.")

        pending = db.session.scalar(
            select(PaymentProof)
            .where(
                PaymentProof.payment_id == payment.id,
                PaymentProof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW,
            )
            .with_for_update()
        )
        if pending is not None:
            raise PaymentProofStateError("A payment proof is already awaiting review.")

        try:
            prepared = prepare_proof_upload(upload)
        except ProofValidationError as exc:
            raise PaymentProofValidationError(str(exc)) from exc

        try:
            store_proof_file(prepared)
        except ProofStorageError as exc:
            raise PaymentProofError(str(exc)) from exc

        proof = PaymentProof(
            payment_id=payment.id,
            proof_filename=prepared.filename,
            mime_type=prepared.mime_type,
            file_size=prepared.file_size,
            status=PAYMENT_PROOF_STATUS_PENDING_REVIEW,
            submitted_at=now,
        )
        db.session.add(proof)
        _commit_or_raise()
        return proof
    except PaymentProofError:
        db.session.rollback()
        _cleanup_prepared_file(prepared)
        raise
    except IntegrityError as exc:
        db.session.rollback()
        _cleanup_prepared_file(prepared)
        raise PaymentProofStateError(
            "A payment proof is already awaiting review or could not be saved."
        ) from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        _cleanup_prepared_file(prepared)
        raise PaymentProofError("Payment proof could not be saved. Please try again.") from exc
    except Exception:
        db.session.rollback()
        _cleanup_prepared_file(prepared)
        raise


def list_payment_proofs(payment_id: int) -> list[PaymentProof]:
    """Return one payment's proof history newest first."""
    statement = (
        select(PaymentProof)
        .where(PaymentProof.payment_id == payment_id)
        .order_by(PaymentProof.submitted_at.desc(), PaymentProof.id.desc())
    )
    return list(db.session.scalars(statement).all())


def list_admin_proofs(
    filters: AdminProofFilters,
    *,
    page: int = 1,
    per_page: int = 20,
):
    """Return a paginated admin review queue with related payment context."""
    conditions = []
    if filters.status is not None:
        conditions.append(PaymentProof.status == filters.status)
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                Order.order_number.ilike(pattern, escape="\\"),
                Payment.payment_reference.ilike(pattern, escape="\\"),
                Order.user.has(User.email.ilike(pattern, escape="\\")),
                Order.user.has(User.full_name.ilike(pattern, escape="\\")),
            )
        )

    statement = (
        select(PaymentProof)
        .join(PaymentProof.payment)
        .join(Payment.order)
        .options(
            joinedload(PaymentProof.payment).joinedload(Payment.order).joinedload(Order.user),
            joinedload(PaymentProof.reviewed_by),
        )
        .where(*conditions)
        .order_by(PaymentProof.submitted_at.desc(), PaymentProof.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_admin_proof(proof_id: int) -> PaymentProof | None:
    """Return one proof with payment, order, customer and reviewer loaded."""
    statement = (
        select(PaymentProof)
        .options(
            joinedload(PaymentProof.payment).joinedload(Payment.order).joinedload(Order.user),
            joinedload(PaymentProof.reviewed_by),
        )
        .where(PaymentProof.id == proof_id)
    )
    return db.session.scalar(statement)


def approve_payment_proof(
    proof_id: int,
    admin_user_id: int,
    *,
    now: datetime | None = None,
) -> ProofReviewResult:
    """Atomically approve evidence and mark the order paid exactly once."""
    now = now or datetime.now(UTC)

    try:
        order, payment, proof = _lock_proof_context(proof_id)

        if proof.status == PAYMENT_PROOF_STATUS_APPROVED:
            if (
                payment.status == PAYMENT_STATUS_PAID
                and order.payment_status == PAYMENT_STATUS_PAID
            ):
                _commit_or_raise()
                return ProofReviewResult(
                    proof,
                    "This payment proof was already approved.",
                    "info",
                )
            raise PaymentProofStateError("The approved proof is inconsistent with payment state.")

        if proof.status != PAYMENT_PROOF_STATUS_PENDING_REVIEW:
            raise PaymentProofStateError("Only pending-review proofs can be approved.")
        if payment.provider != PAYMENT_PROVIDER_MANUAL_TRANSFER:
            raise PaymentProofStateError("This payment is not a manual bank transfer.")
        if payment.status == PAYMENT_STATUS_PAID:
            raise PaymentProofStateError("This payment is already paid.")

        if order.status == ORDER_STATUS_CANCELLED:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This order is cancelled.")

        if order.payment_status == PAYMENT_STATUS_PAID:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This order has already been paid.")

        if payment.status == PAYMENT_STATUS_EXPIRED:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This payment attempt has expired.")
        if payment.status != PAYMENT_STATUS_PENDING:
            raise PaymentProofStateError("This payment is no longer pending.")
        if now >= payment.expires_at:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This payment attempt has expired.")
        if order.status not in PAYMENT_ELIGIBLE_ORDER_STATUSES:
            raise PaymentProofStateError("This order is no longer eligible for payment.")
        if order.payment_status != PAYMENT_STATUS_UNPAID:
            raise PaymentProofStateError("This order is not eligible for payment.")

        expected_amount = order.total.quantize(_CENT)
        if payment.amount != expected_amount or payment.currency != PAYMENT_CURRENCY_IDR:
            raise PaymentProofStateError("The transfer amount does not match the order total.")

        other_paid = db.session.scalar(
            select(Payment.id)
            .where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PAID,
                Payment.id != payment.id,
            )
            .with_for_update(of=Payment)
            .limit(1)
        )
        if other_paid is not None:
            _expire_payment_and_proofs(payment, now)
            _commit_or_raise()
            raise PaymentProofStateError("This order has already been paid by another attempt.")

        payment.status = PAYMENT_STATUS_PAID
        payment.paid_at = now
        payment.provider_reference = f"MANUAL-{payment.payment_reference}"
        order.payment_status = PAYMENT_STATUS_PAID
        proof.status = PAYMENT_PROOF_STATUS_APPROVED
        proof.reviewed_by_user_id = admin_user_id
        proof.reviewed_at = now
        proof.rejection_reason = None

        other_pending = db.session.scalars(
            select(Payment)
            .where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PENDING,
                Payment.id != payment.id,
            )
            .with_for_update()
        ).all()
        for attempt in other_pending:
            _expire_payment_and_proofs(attempt, now)

        _commit_or_raise()
        return ProofReviewResult(
            proof,
            "Payment proof approved and the order marked paid.",
            "success",
        )
    except PaymentProofError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        db.session.rollback()
        raise PaymentProofStateError("Payment proof could not be approved.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentProofStateError("Payment proof could not be approved.") from exc


def reject_payment_proof(
    proof_id: int,
    admin_user_id: int,
    reason: object,
    *,
    now: datetime | None = None,
) -> ProofReviewResult:
    """Reject one pending proof with a mandatory reason and preserve history."""
    cleaned_reason = _clean_rejection_reason(reason)
    now = now or datetime.now(UTC)

    try:
        _order, _payment, proof = _lock_proof_context(proof_id)

        if proof.status == PAYMENT_PROOF_STATUS_REJECTED:
            _commit_or_raise()
            return ProofReviewResult(
                proof,
                "This payment proof was already rejected.",
                "info",
            )
        if proof.status != PAYMENT_PROOF_STATUS_PENDING_REVIEW:
            raise PaymentProofStateError("Only pending-review proofs can be rejected.")

        proof.status = PAYMENT_PROOF_STATUS_REJECTED
        proof.reviewed_by_user_id = admin_user_id
        proof.reviewed_at = now
        proof.rejection_reason = cleaned_reason
        _commit_or_raise()
        return ProofReviewResult(
            proof,
            "Payment proof rejected. The customer may submit replacement evidence.",
            "success",
        )
    except PaymentProofError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentProofStateError("Payment proof could not be rejected.") from exc


def _lock_payment_context_by_reference(payment_reference: str) -> tuple[Order, Payment]:
    """Lock Order -> Payment for one payment reference."""
    normalized = payment_reference.strip().upper()
    order_id = db.session.scalar(
        select(Payment.order_id).where(Payment.payment_reference == normalized)
    )
    if order_id is None:
        raise PaymentProofNotFound("Payment proof not found.")

    order = db.session.scalar(select(Order).where(Order.id == order_id).with_for_update())
    payment = db.session.scalar(
        select(Payment).where(Payment.payment_reference == normalized).with_for_update()
    )
    if order is None or payment is None or payment.order_id != order.id:
        raise PaymentProofNotFound("Payment proof not found.")
    return order, payment


def _lock_proof_context(proof_id: int) -> tuple[Order, Payment, PaymentProof]:
    """Lock Order -> Payment -> PaymentProof for one review action."""
    context = db.session.execute(
        select(PaymentProof.payment_id, Payment.order_id)
        .join(Payment, PaymentProof.payment_id == Payment.id)
        .where(PaymentProof.id == proof_id)
    ).first()
    if context is None:
        raise PaymentProofNotFound("Payment proof not found.")

    payment_id, order_id = context
    order = db.session.scalar(select(Order).where(Order.id == order_id).with_for_update())
    payment = db.session.scalar(select(Payment).where(Payment.id == payment_id).with_for_update())
    proof = db.session.scalar(
        select(PaymentProof).where(PaymentProof.id == proof_id).with_for_update()
    )
    if order is None or payment is None or proof is None:
        raise PaymentProofNotFound("Payment proof not found.")
    if proof.payment_id != payment.id or payment.order_id != order.id:
        raise PaymentProofNotFound("Payment proof not found.")
    return order, payment, proof


def _expire_payment_and_proofs(payment: Payment, now: datetime) -> None:
    """Expire one locked payment and cancel its pending-review proof."""
    payment.status = PAYMENT_STATUS_EXPIRED
    payment.expired_at = now
    pending_proofs = db.session.scalars(
        select(PaymentProof)
        .where(
            PaymentProof.payment_id == payment.id,
            PaymentProof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW,
        )
        .with_for_update()
    ).all()
    for proof in pending_proofs:
        proof.status = PAYMENT_PROOF_STATUS_CANCELLED


def _clean_rejection_reason(value: object) -> str:
    if not isinstance(value, str):
        raise PaymentProofValidationError("A rejection reason is required.")
    cleaned = value.strip()
    if not cleaned:
        raise PaymentProofValidationError("A rejection reason is required.")
    if len(cleaned) > _MAX_REJECTION_REASON:
        raise PaymentProofValidationError(
            f"Rejection reason must be {_MAX_REJECTION_REASON} characters or fewer."
        )
    return cleaned


def _cleanup_prepared_file(prepared: PreparedProof | None) -> None:
    if prepared is None:
        return
    with contextlib.suppress(ProofStorageError):
        delete_proof_file(prepared.filename)


def _commit_or_raise() -> None:
    """Commit proof review state and translate database failures."""
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise PaymentProofStateError("The payment proof state changed. Please retry.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise PaymentProofError("Payment proof could not be saved. Please try again.") from exc


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
