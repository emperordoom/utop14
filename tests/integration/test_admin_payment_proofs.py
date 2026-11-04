"""Integration tests for admin payment-proof review and private evidence access."""

from __future__ import annotations

import io
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from PIL import Image
from sqlalchemy import func, select
from werkzeug.datastructures import FileStorage

from app.extensions import db
from app.models import Order, Payment, PaymentProof, User
from app.models.payment import PAYMENT_STATUS_EXPIRED, PAYMENT_STATUS_PAID
from app.models.payment_proof import (
    PAYMENT_PROOF_STATUS_APPROVED,
    PAYMENT_PROOF_STATUS_CANCELLED,
    PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    PAYMENT_PROOF_STATUS_REJECTED,
)
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.orders import cancel_customer_order
from app.services.payment_proofs import (
    AdminProofFilters,
    approve_payment_proof,
    list_admin_proofs,
    upload_payment_proof,
)
from app.services.payments import create_manual_payment_attempt


def _image_bytes(
    fmt: str = "PNG",
    *,
    size: tuple[int, int] = (64, 64),
    colour: str = "#22c55e",
) -> bytes:
    image = Image.new("RGB", size, colour)
    output = io.BytesIO()
    image.save(output, format=fmt)
    return output.getvalue()


def _pdf_bytes() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 1\n0000000000 65535 f \n"
        b"trailer\n<< /Size 1 >>\n"
        b"startxref\n9\n%%EOF\n"
    )


def _manual_payment(
    user: User,
    order: Order,
    *,
    key: str = "admin-proof-manual-key",
) -> Payment:
    return create_manual_payment_attempt(user.id, order.order_number, key)


def _upload_proof(
    user: User,
    payment: Payment,
    *,
    payload: bytes | None = None,
    filename: str = "proof.png",
    content_type: str = "image/png",
) -> PaymentProof:
    upload = FileStorage(
        stream=io.BytesIO(payload if payload is not None else _image_bytes()),
        filename=filename,
        content_type=content_type,
    )
    return upload_payment_proof(user.id, payment.payment_reference, upload)


def _login_admin(
    make_user: Callable[..., User],
    login: Callable[..., object],
    *,
    email: str = "proof-review-admin@example.com",
) -> User:
    admin = make_user(email=email, role=ROLE_ADMIN)
    login(email)
    return admin


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


def test_admin_can_view_pending_queue_and_proof_detail(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-queue-customer@example.com", full_name="Queue Customer")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    _login_admin(make_user, login, email="proof-queue-admin@example.com")

    response = client.get("/admin/payment-proofs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert order.order_number in html
    assert payment.payment_reference in html
    assert "Queue Customer" in html
    assert "Pending Review" in html
    assert "Review" in html
    assert proof.proof_filename not in html

    detail = client.get(f"/admin/payment-proofs/{proof.id}")
    assert detail.status_code == 200
    detail_html = detail.get_data(as_text=True)
    assert "Approve proof" in detail_html
    assert "Reject proof" in detail_html
    assert "Download" not in detail_html or proof.mime_type == "application/pdf"
    assert proof.proof_filename not in detail_html
    assert "data-confirm=" in detail_html


def test_admin_proof_list_filters_and_pagination(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-list-customer@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    _upload_proof(customer, payment)
    now = datetime.now(UTC)
    for index in range(21):
        db.session.add(
            PaymentProof(
                payment_id=payment.id,
                proof_filename=f"{index:032x}.pdf",
                mime_type="application/pdf",
                file_size=100,
                status=PAYMENT_PROOF_STATUS_REJECTED,
                submitted_at=now - timedelta(minutes=index),
                rejection_reason="Historical rejection",
            )
        )
    db.session.commit()
    _login_admin(make_user, login, email="proof-list-admin@example.com")

    default_html = client.get("/admin/payment-proofs").get_data(as_text=True)
    assert payment.payment_reference in default_html
    assert "Historical rejection" not in default_html

    rejected_page = client.get("/admin/payment-proofs?status=rejected")
    assert rejected_page.status_code == 200
    assert "Page 1 / 2" in rejected_page.get_data(as_text=True)

    second_page = client.get("/admin/payment-proofs?status=rejected&page=2")
    assert second_page.status_code == 200

    filters = AdminProofFilters.from_values(status="rejected")
    page_one = list_admin_proofs(filters, page=1)
    page_two = list_admin_proofs(filters, page=2)
    assert len(page_one.items) == 20
    assert len(page_two.items) == 1

    all_html = client.get("/admin/payment-proofs?status=all").get_data(as_text=True)
    assert payment.payment_reference in all_html
    assert "Historical rejection" not in all_html

    search_html = client.get(
        "/admin/payment-proofs",
        query_string={"status": "all", "q": order.order_number},
    ).get_data(as_text=True)
    assert payment.payment_reference in search_html


def test_admin_can_approve_valid_proof_atomically(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-approve-customer@example.com")
    admin = _login_admin(make_user, login, email="proof-approve-admin@example.com")
    order = make_order(customer)
    first_payment = _manual_payment(customer, order, key="approve-first-key")
    first_proof = _upload_proof(customer, first_payment)
    second_payment = _manual_payment(customer, order, key="approve-second-key")
    second_proof = _upload_proof(
        customer,
        second_payment,
        payload=_image_bytes("JPEG"),
        filename="second.jpg",
        content_type="image/jpeg",
    )
    token = csrf_token(f"/admin/payment-proofs/{first_proof.id}")

    response = client.post(
        f"/admin/payment-proofs/{first_proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "approved" in response.get_data(as_text=True).lower()

    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, first_payment.id)
    refreshed_order = db.session.get(Order, order.id)
    refreshed_proof = db.session.get(PaymentProof, first_proof.id)
    other_payment = db.session.get(Payment, second_payment.id)
    other_proof = db.session.get(PaymentProof, second_proof.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_PAID
    assert refreshed_payment.paid_at is not None
    assert refreshed_payment.provider_reference is not None
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "paid"
    assert refreshed_order.status == "pending"
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_APPROVED
    assert refreshed_proof.reviewed_by_user_id == admin.id
    assert refreshed_proof.reviewed_at is not None
    assert other_payment is not None
    assert other_payment.status == PAYMENT_STATUS_EXPIRED
    assert other_proof is not None
    assert other_proof.status == PAYMENT_PROOF_STATUS_CANCELLED
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )

    second_attempt = client.post(
        f"/admin/payment-proofs/{second_proof.id}/approve",
        data={"csrf_token": csrf_token("/auth/account")},
        follow_redirects=True,
    )
    assert second_attempt.status_code == 200
    assert "pending-review" in second_attempt.get_data(as_text=True).lower()
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )

    _logout(client, csrf_token)
    login(customer.email)
    customer_detail = client.get(f"/payments/{first_payment.payment_reference}")
    assert customer_detail.status_code == 200
    assert "Payment approved. The order payment status is paid." in customer_detail.get_data(
        as_text=True
    )


def test_concurrent_approval_of_same_proof_is_safe(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-concurrent-customer@example.com")
    admin = make_user(email="proof-concurrent-admin@example.com", role=ROLE_ADMIN)
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    proof_id = proof.id
    admin_id = admin.id
    order_id = order.id
    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[str] = []

    def attempt() -> None:
        with app.app_context():
            barrier.wait()
            try:
                result = approve_payment_proof(proof_id, admin_id)
                results.append(result.proof.status)
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
    assert results == [PAYMENT_PROOF_STATUS_APPROVED, PAYMENT_PROOF_STATUS_APPROVED]
    db.session.expire_all()
    assert db.session.get(PaymentProof, proof_id).status == PAYMENT_PROOF_STATUS_APPROVED
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order_id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )


def test_repeated_approval_is_idempotent(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-repeat-approve-customer@example.com")
    _login_admin(make_user, login, email="proof-repeat-approve-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    token = csrf_token(f"/admin/payment-proofs/{proof.id}")

    first = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    second = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert "already approved" in second.get_data(as_text=True).lower()
    assert (
        db.session.scalar(
            select(func.count(Payment.id)).where(
                Payment.order_id == order.id,
                Payment.status == PAYMENT_STATUS_PAID,
            )
        )
        == 1
    )


def test_expired_payment_cannot_be_approved(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-expired-approve-customer@example.com")
    _login_admin(make_user, login, email="proof-expired-approve-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    payment.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.session.commit()
    token = csrf_token(f"/admin/payment-proofs/{proof.id}")

    response = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "expired" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_EXPIRED
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_CANCELLED
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "unpaid"


def test_approval_rejects_payment_amount_mismatch(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-amount-mismatch-customer@example.com")
    _login_admin(make_user, login, email="proof-amount-mismatch-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    payment.amount = Decimal("1.00")
    db.session.commit()
    token = csrf_token(f"/admin/payment-proofs/{proof.id}")

    response = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "amount" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_order = db.session.get(Order, order.id)
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == "pending"
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "unpaid"
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW


def test_cancelled_order_cannot_be_approved(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-cancel-approve-customer@example.com")
    _login_admin(make_user, login, email="proof-cancel-approve-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    cancel_customer_order(customer.id, order.order_number, reason="Cancelled before review")
    token = csrf_token("/auth/account")

    response = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_EXPIRED
    assert refreshed_order is not None
    assert refreshed_order.status == "cancelled"
    assert refreshed_order.payment_status == "unpaid"


def test_rejection_requires_reason_and_preserves_history(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-reject-customer@example.com")
    admin = _login_admin(make_user, login, email="proof-reject-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)
    token = csrf_token(f"/admin/payment-proofs/{proof.id}")

    missing = client.post(
        f"/admin/payment-proofs/{proof.id}/reject",
        data={"csrf_token": token, "reason": ""},
        follow_redirects=True,
    )
    assert missing.status_code == 200
    assert "rejection reason is required" in missing.get_data(as_text=True).lower()
    db.session.expire_all()
    assert db.session.get(PaymentProof, proof.id).status == PAYMENT_PROOF_STATUS_PENDING_REVIEW

    rejected = client.post(
        f"/admin/payment-proofs/{proof.id}/reject",
        data={"csrf_token": token, "reason": "Amount is not visible."},
        follow_redirects=True,
    )
    assert rejected.status_code == 200
    assert "rejected" in rejected.get_data(as_text=True).lower()
    db.session.expire_all()
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_REJECTED
    assert refreshed_proof.rejection_reason == "Amount is not visible."
    assert refreshed_proof.reviewed_by_user_id == admin.id
    assert refreshed_payment is not None
    assert refreshed_payment.status == "pending"
    assert refreshed_order is not None
    assert refreshed_order.payment_status == "unpaid"

    history = client.get("/admin/payment-proofs?status=all")
    assert "Rejected" in history.get_data(as_text=True)


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_customer_and_operator_cannot_list_or_view_proofs(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    role: str,
) -> None:
    customer = make_user(email=f"proof-list-rbac-customer-{role}@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order, key=f"list-rbac-key-{role}")
    proof = _upload_proof(customer, payment)
    email = f"proof-list-rbac-{role}@example.com"
    make_user(email=email, role=role)
    login(email)

    assert client.get("/admin/payment-proofs").status_code == 403
    assert client.get(f"/admin/payment-proofs/{proof.id}").status_code == 403


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_customer_and_operator_cannot_review(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    role: str,
) -> None:
    customer = make_user(email=f"proof-rbac-customer-{role}@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order, key=f"rbac-key-{role}")
    proof = _upload_proof(customer, payment)
    email = f"proof-rbac-{role}@example.com"
    make_user(email=email, role=role)
    login(email)
    token = csrf_token("/auth/account")

    approve = client.post(
        f"/admin/payment-proofs/{proof.id}/approve",
        data={"csrf_token": token},
    )
    reject = client.post(
        f"/admin/payment-proofs/{proof.id}/reject",
        data={"csrf_token": token, "reason": "Not allowed"},
    )

    assert approve.status_code == 403
    assert reject.status_code == 403
    db.session.expire_all()
    assert db.session.get(PaymentProof, proof.id).status == PAYMENT_PROOF_STATUS_PENDING_REVIEW


def test_admin_review_mutations_require_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-csrf-customer@example.com")
    _login_admin(make_user, login, email="proof-csrf-admin@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)

    approve = client.post(f"/admin/payment-proofs/{proof.id}/approve", data={})
    reject = client.post(
        f"/admin/payment-proofs/{proof.id}/reject",
        data={"reason": "No token"},
    )

    assert approve.status_code == 400
    assert reject.status_code == 400
    db.session.expire_all()
    assert db.session.get(PaymentProof, proof.id).status == PAYMENT_PROOF_STATUS_PENDING_REVIEW


def test_admin_can_access_private_image_and_pdf_evidence(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-file-customer@example.com")
    _login_admin(make_user, login, email="proof-file-admin@example.com")
    order = make_order(customer)
    image_payment = _manual_payment(customer, order, key="file-image-key")
    image_proof = _upload_proof(customer, image_payment)
    pdf_payment = _manual_payment(customer, order, key="file-pdf-key")
    pdf_proof = _upload_proof(
        customer,
        pdf_payment,
        payload=_pdf_bytes(),
        filename="proof.pdf",
        content_type="application/pdf",
    )

    image_response = client.get(f"/admin/payment-proofs/{image_proof.id}/file")
    assert image_response.status_code == 200
    assert image_response.mimetype == "image/png"
    assert image_response.headers["X-Content-Type-Options"] == "nosniff"
    assert image_response.headers["Cache-Control"] == "private, no-store"
    assert image_response.data == (payment_proof_storage / image_proof.proof_filename).read_bytes()
    # Images render inline and never disclose the generated storage filename.
    assert "Content-Disposition" not in image_response.headers
    assert image_proof.proof_filename not in str(dict(image_response.headers))

    pdf_response = client.get(f"/admin/payment-proofs/{pdf_proof.id}/file")
    assert pdf_response.status_code == 200
    assert pdf_response.mimetype == "application/pdf"
    assert "attachment" in pdf_response.headers["Content-Disposition"].lower()
    assert pdf_proof.proof_filename not in pdf_response.headers["Content-Disposition"]

    (payment_proof_storage / image_proof.proof_filename).unlink()
    assert client.get(f"/admin/payment-proofs/{image_proof.id}/file").status_code == 404


def test_anonymous_review_mutations_redirect_to_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    token = csrf_token("/auth/login")

    approve = client.post(
        "/admin/payment-proofs/1/approve",
        data={"csrf_token": token},
    )
    reject = client.post(
        "/admin/payment-proofs/1/reject",
        data={"csrf_token": token, "reason": "Anonymous"},
    )

    assert approve.status_code == 302
    assert approve.headers["Location"].startswith("/auth/login")
    assert reject.status_code == 302
    assert reject.headers["Location"].startswith("/auth/login")


def test_private_proof_file_requires_admin_role(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    customer = make_user(email="proof-file-rbac-customer@example.com")
    order = make_order(customer)
    payment = _manual_payment(customer, order)
    proof = _upload_proof(customer, payment)

    make_user(email="proof-file-operator@example.com", role=ROLE_OPERATOR)
    login("proof-file-operator@example.com")
    assert client.get(f"/admin/payment-proofs/{proof.id}/file").status_code == 403
    _logout(client, csrf_token)
    login("proof-file-rbac-customer@example.com")
    assert client.get(f"/admin/payment-proofs/{proof.id}/file").status_code == 403
    _logout(client, csrf_token)
    assert client.get(f"/admin/payment-proofs/{proof.id}/file").status_code == 302
