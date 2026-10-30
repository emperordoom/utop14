"""Customer payment initiation and simulated processing routes."""

from __future__ import annotations

import secrets

from flask import abort, flash, redirect, render_template, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.models.payment import PAYMENT_PROVIDER_SIMULATED, PAYMENT_STATUS_PENDING
from app.payments import payments_bp
from app.payments.forms import PaymentInitiationForm, SimulationForm
from app.services.checkout import get_order_for_user
from app.services.payments import (
    PaymentNotFound,
    PaymentStateError,
    PaymentUnavailable,
    can_pay_order,
    create_payment_attempt,
    get_payment_for_user,
    payment_provider_available,
    process_simulated_payment,
    simulation_enabled,
)


def _pay_context(order, form: PaymentInitiationForm) -> dict[str, object]:
    return {
        "order": order,
        "form": form,
        "payments_available": payment_provider_available(),
        "simulation_enabled": simulation_enabled(),
        "eligible": can_pay_order(order),
        "payment_attempts": order.payments,
    }


@payments_bp.get("/orders/<order_number>/pay")
@login_required
def pay(order_number: str) -> ResponseReturnValue:
    """Render the owner's payment page without changing payment state."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    form = PaymentInitiationForm()
    form.idempotency_key.data = secrets.token_urlsafe(32)
    context = _pay_context(order, form)
    if not context["payments_available"]:
        return render_template("payments/pay.html", **context), 503
    return render_template("payments/pay.html", **context)


@payments_bp.post("/orders/<order_number>/payments")
@login_required
def create_attempt(order_number: str) -> ResponseReturnValue:
    """Create a server-priced pending payment attempt with idempotency."""
    order = get_order_for_user(current_user.id, order_number)
    if order is None:
        abort(404)

    form = PaymentInitiationForm()
    if not payment_provider_available():
        return render_template("payments/pay.html", **_pay_context(order, form)), 503

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
        return render_template("payments/pay.html", **_pay_context(order, form)), 503

    return redirect(url_for("payments.detail", payment_reference=payment.payment_reference))


@payments_bp.get("/payments/<payment_reference>")
@login_required
def detail(payment_reference: str) -> ResponseReturnValue:
    """Show one owned payment attempt without mutating it."""
    payment = get_payment_for_user(current_user.id, payment_reference)
    if payment is None:
        abort(404)

    simulation_allowed = (
        simulation_enabled()
        and payment.provider == PAYMENT_PROVIDER_SIMULATED
        and payment.status == PAYMENT_STATUS_PENDING
    )
    return render_template(
        "payments/detail.html",
        payment=payment,
        order=payment.order,
        simulation_form=SimulationForm(),
        simulation_allowed=simulation_allowed,
        simulation_enabled=simulation_enabled(),
    )


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
