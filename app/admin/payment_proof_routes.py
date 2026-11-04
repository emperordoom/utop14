"""Admin-only manual-transfer proof review and private evidence delivery."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, send_file, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user

from app.admin import admin_bp
from app.admin.forms import ActionForm, PaymentProofRejectForm
from app.auth.permissions import role_required
from app.models.payment_proof import PAYMENT_PROOF_STATUSES
from app.models.user import ROLE_ADMIN
from app.services.payment_proofs import (
    AdminProofFilters,
    PaymentProofError,
    PaymentProofNotFound,
    PaymentProofStateError,
    approve_payment_proof,
    get_admin_proof,
    list_admin_proofs,
    reject_payment_proof,
)
from app.services.proof_storage import (
    PROOF_MIME_TYPES,
    ProofStorageError,
    proof_file_exists,
    proof_file_path,
)


@admin_bp.get("/admin/payment-proofs")
@role_required(ROLE_ADMIN)
def payment_proof_list() -> ResponseReturnValue:
    """Show the pending review queue and review history."""
    filters = AdminProofFilters.from_values(
        status=request.args.get("status", "pending_review"),
        q=request.args.get("q"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_admin_proofs(filters, page=page)
    return render_template(
        "admin/payment_proof_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        statuses=PAYMENT_PROOF_STATUSES,
    )


@admin_bp.get("/admin/payment-proofs/<int:proof_id>")
@role_required(ROLE_ADMIN)
def payment_proof_detail(proof_id: int) -> ResponseReturnValue:
    """Show one proof, its payment context and review controls."""
    proof = get_admin_proof(proof_id)
    if proof is None:
        abort(404)

    return render_template(
        "admin/payment_proof_detail.html",
        proof=proof,
        approve_form=ActionForm(),
        reject_form=PaymentProofRejectForm(),
    )


@admin_bp.get("/admin/payment-proofs/<int:proof_id>/file")
@role_required(ROLE_ADMIN)
def payment_proof_file(proof_id: int) -> ResponseReturnValue:
    """Serve one private proof after resolving its generated filename from DB."""
    proof = get_admin_proof(proof_id)
    if (
        proof is None
        or proof.mime_type not in PROOF_MIME_TYPES
        or not proof_file_exists(proof.proof_filename)
    ):
        abort(404)

    try:
        path = proof_file_path(proof.proof_filename)
        is_pdf = proof.mime_type == "application/pdf"
        response = send_file(
            path,
            mimetype=proof.mime_type,
            as_attachment=is_pdf,
            download_name=(f"{proof.payment.payment_reference}-proof.pdf" if is_pdf else None),
            conditional=True,
            max_age=0,
        )
    except (ProofStorageError, OSError):
        abort(404)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    if not is_pdf:
        # Werkzeug always emits ``inline; filename=<basename>``; dropping the
        # header keeps the internal storage filename out of the response while
        # still letting the browser render the evidence inline (RFC 6266).
        response.headers.pop("Content-Disposition", None)
    return response


@admin_bp.post("/admin/payment-proofs/<int:proof_id>/approve")
@role_required(ROLE_ADMIN)
def payment_proof_approve(proof_id: int) -> ResponseReturnValue:
    """Approve one pending proof and mark its order paid atomically."""
    form = ActionForm()
    if not form.validate_on_submit():
        flash("The payment proof could not be approved.", "error")
        return redirect(url_for("admin.payment_proof_detail", proof_id=proof_id))

    try:
        result = approve_payment_proof(proof_id, current_user.id)
    except PaymentProofNotFound:
        abort(404)
    except (PaymentProofStateError, PaymentProofError) as exc:
        flash(str(exc), "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.payment_proof_detail", proof_id=proof_id))


@admin_bp.post("/admin/payment-proofs/<int:proof_id>/reject")
@role_required(ROLE_ADMIN)
def payment_proof_reject(proof_id: int) -> ResponseReturnValue:
    """Reject one pending proof with a mandatory reason."""
    form = PaymentProofRejectForm()
    if not form.validate_on_submit():
        flash("A rejection reason is required.", "error")
        return redirect(url_for("admin.payment_proof_detail", proof_id=proof_id))

    try:
        result = reject_payment_proof(
            proof_id,
            current_user.id,
            form.reason.data,
        )
    except PaymentProofNotFound:
        abort(404)
    except (PaymentProofStateError, PaymentProofError) as exc:
        flash(str(exc), "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.payment_proof_detail", proof_id=proof_id))
