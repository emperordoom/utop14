"""Customer payment initiation, manual proof upload and simulation routes."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from flask import abort, flash, redirect, render_template, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.models.payment import (
    PAYMENT_PROVIDER_MANUAL_TRANSFER,
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_PENDING,
)
from app.models.payment_proof import PAYMENT_PROOF_STATUS_PENDING_REVIEW
from app.payments import payments_bp
from app.payments.forms import PaymentInitiationForm, PaymentProofForm, SimulationForm
from app.services.checkout import get_order_for_user
from app.services.payment_proofs import (
    PaymentProofError,
    PaymentProofNotFound,
    PaymentProofStateError,
    PaymentProofValidationError,
    list_payment_proofs,
    upload_payment_proof,
)
from app.services.payments import (
    PAYMENT_ELIGIBLE_ORDER_STATUSES,
    PaymentNotFound,
    PaymentStateError,
    PaymentUnavailable,
    can_pay_order,
    create_manual_payment_attempt,
    create_payment_attempt,
    get_payment_for_user,
    manual_transfer_available,
    manual_transfer_details,
    manual_transfer_ttl_hours,
    payment_provider_available,
    process_simulated_payment,
    simulation_enabled,
)


def _new_payment_forms() -> tuple[PaymentInitiationForm, PaymentInitiationForm]:
    form = PaymentInitiationForm()
    form.idempotency_key.data = secrets.token_urlsafe(32)
    manual_form = PaymentInitiationForm()
    manual_form.idempotency_key.data = secrets.token_urlsafe(32)
    return form, manual_form


def _pay_context(
    order,
    form: PaymentInitiationForm,
    manual_form: PaymentInitiationForm,
) -> dict[str, object]:
    simulated_available = payment_provider_available()
    manual_available = manual_transfer_available()
    return {
        "order": order,
        "form": form,
        "manual_form": manual_form,
        "simulated_available": simulated_available,
        "manual_available": manual_available,
        "manual_details": manual_transfer_details(),
        "manual_ttl_hours": manual_transfer_ttl_hours(),
        "payments_available": simulated_available or manual_available,
        "simulation_enabled": simulation_enabled(),
        "eligible": can_pay_order(order),
        "payment_attempts": order.payments,
    }


def _payment_detail_context(
    payment,
    *,
    proof_form: PaymentProofForm | None = None,
) -> dict[str, object]:
    order = payment.order
    proofs = list_payment_proofs(payment.id)
    details = (
        manual_transfer_details() if payment.provider == PAYMENT_PROVIDER_MANUAL_TRANSFER else None
    )
    payment_expired = (
        payment.status == PAYMENT_STATUS_PENDING and datetime.now(UTC) >= payment.expires_at
    )
    pending_proof = next(
        (proof for proof in proofs if proof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW),
        None,
    )
    can_upload_proof = (
        payment.provider == PAYMENT_PROVIDER_MANUAL_TRANSFER
        and details is not None
        and payment.status == PAYMENT_STATUS_PENDING
        and not payment_expired
        and order.status in PAYMENT_ELIGIBLE_ORDER_STATUSES
        and order.payment_status == "unpaid"
        and pending_proof is None
    )
    simulation_allowed = (
        simulation_enabled()
        and payment.provider == PAYMENT_PROVIDER_SIMULATED
        and payment.status == PAYMENT_STATUS_PENDING
    )
    return {
        "payment": payment,
        "order": order,
        "proofs": proofs,
        "proof_form": proof_form or PaymentProofForm(),
        "manual_details": details,
        "manual_available": details is not None,
        "payment_expired": payment_expired,
        "pending_proof": pending_proof,
        "can_upload_proof": can_upload_proof,
        "simulation_form": SimulationForm(),
        "simulation_allowed": simulation_allowed,
        "simulation_enabled": simulation_enabled(),
    }


@payments_bp.get("/orders/<order_number>/pay")
@login_required
def pay(order_number: str) -> ResponseReturnValue:
    """Render the owner's payment options without changing payment state."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    form, manual_form = _new_payment_forms()
    context = _pay_context(order, form, manual_form)
    if not context["payments_available"]:
        return render_template("payments/pay.html", **context), 503
    return render_template("payments/pay.html", **context)


@payments_bp.post("/orders/<order_number>/payments")
@login_required
def create_attempt(order_number: str) -> ResponseReturnValue:
    """Create a server-priced simulated pending attempt with idempotency."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    form = PaymentInitiationForm()
    if not payment_provider_available():
        _, manual_form = _new_payment_forms()
        return render_template(
            "payments/pay.html",
            **_pay_context(order, form, manual_form),
        ), 503

    if not form.validate_on_submit():
        flash("Start a new payment attempt from the payment page.", "error")
        return redirect(url_for("payments.pay", order_number=order_number))

    try:
        payment = create_payment_attempt(
            current_user.id,
            order_number,
            form.idempotency_key.data,
        )
    except PaymentNotFound:
        abort(404)
    except PaymentStateError as exc:
        flash(str(exc), "error")
        return redirect(url_for("payments.pay", order_number=order_number))
    except PaymentUnavailable:
        _, manual_form = _new_payment_forms()
        return render_template(
            "payments/pay.html",
            **_pay_context(order, form, manual_form),
        ), 503

    return redirect(url_for("payments.detail", payment_reference=payment.payment_reference))


@payments_bp.post("/orders/<order_number>/manual-payments")
@login_required
def create_manual_attempt(order_number: str) -> ResponseReturnValue:
    """Create a manual bank-transfer attempt when complete bank details exist."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    form = PaymentInitiationForm()
    if not manual_transfer_available():
        flash(
            "Manual bank transfer is unavailable because bank details are not configured.",
            "error",
        )
        form, _ = _new_payment_forms()
        return render_template(
            "payments/pay.html",
            **_pay_context(order, form, form),
        ), 503

    if not form.validate_on_submit():
        flash("Start a new bank-transfer attempt from the payment page.", "error")
        return redirect(url_for("payments.pay", order_number=order_number))

    try:
        payment = create_manual_payment_attempt(
            current_user.id,
            order_number,
            form.idempotency_key.data,
        )
    except PaymentNotFound:
        abort(404)
    except PaymentStateError as exc:
        flash(str(exc), "error")
        return redirect(url_for("payments.pay", order_number=order_number))
    except PaymentUnavailable:
        flash(
            "Manual bank transfer is unavailable because bank details are not configured.",
            "error",
        )
        form, _ = _new_payment_forms()
        return render_template(
            "payments/pay.html",
            **_pay_context(order, form, form),
        ), 503

    return redirect(url_for("payments.detail", payment_reference=payment.payment_reference))


@payments_bp.get("/payments/<payment_reference>")
@login_required
def detail(payment_reference: str) -> ResponseReturnValue:
    """Show one owned payment attempt without mutating it."""
    payment = get_payment_for_user(current_user.id, payment_reference)
    if payment is None:
        abort(404)

    return render_template(
        "payments/detail.html",
        **_payment_detail_context(payment),
    )


@payments_bp.post("/payments/<payment_reference>/proof")
@login_required
def upload_proof(payment_reference: str) -> ResponseReturnValue:
    """Upload a replacement or first manual-transfer proof for review."""
    payment = get_payment_for_user(current_user.id, payment_reference)
    if payment is None:
        abort(404)

    form = PaymentProofForm()
    if not form.validate_on_submit():
        return render_template(
            "payments/detail.html",
            **_payment_detail_context(payment, proof_form=form),
        )

    try:
        upload_payment_proof(
            current_user.id,
            payment_reference,
            form.proof.data,
        )
    except PaymentProofNotFound:
        abort(404)
    except PaymentProofValidationError as exc:
        form.proof.errors.append(str(exc))
        return render_template(
            "payments/detail.html",
            **_payment_detail_context(payment, proof_form=form),
        )
    except (PaymentProofStateError, PaymentProofError) as exc:
        flash(str(exc), "error")
    else:
        flash("Payment proof submitted for review.", "success")

    return redirect(url_for("payments.detail", payment_reference=payment_reference))


@payments_bp.post("/payments/<payment_reference>/simulate")
@login_required
def simulate(payment_reference: str) -> ResponseReturnValue:
    """Run a deterministic simulated outcome in development/testing only."""
    if not simulation_enabled():
        abort(404)

    form = SimulationForm()
    if not form.validate_on_submit():
        flash("Choose a valid simulated outcome.", "error")
        return redirect(url_for("payments.detail", payment_reference=payment_reference))

    try:
        result = process_simulated_payment(
            current_user.id,
            payment_reference,
            form.outcome.data,
        )
    except PaymentNotFound:
        abort(404)
    except PaymentStateError as exc:
        flash(str(exc), "error")
    except PaymentUnavailable:
        abort(503)
    else:
        flash(result.message, result.category)

    return redirect(url_for("payments.detail", payment_reference=payment_reference))
