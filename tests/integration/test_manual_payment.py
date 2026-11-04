"""Integration tests for manual bank-transfer initiation and proof uploads."""

from __future__ import annotations

import io
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from PIL import Image
from sqlalchemy import func, select

from app.extensions import db
from app.models import Order, Payment, PaymentProof, User
from app.models.payment import (
    PAYMENT_METHOD_BANK_TRANSFER,
    PAYMENT_METHOD_SIMULATED,
    PAYMENT_PROVIDER_MANUAL_TRANSFER,
    PAYMENT_PROVIDER_SIMULATED,
    PAYMENT_STATUS_EXPIRED,
    PAYMENT_STATUS_PENDING,
)
from app.models.payment_proof import (
    PAYMENT_PROOF_STATUS_CANCELLED,
    PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    PAYMENT_PROOF_STATUS_REJECTED,
)
from app.models.user import ROLE_ADMIN
from app.services.orders import cancel_customer_order
from app.services.payment_proofs import PaymentProofError, reject_payment_proof
from app.services.payments import (
    create_manual_payment_attempt,
    create_payment_attempt,
    expire_payment_attempt,
    manual_transfer_details,
)

PROOF_FILENAME_PATTERN = re.compile(r"^[0-9a-f]{32}\.(jpg|png|webp|pdf)$")


def _image_bytes(
    fmt: str = "PNG",
    *,
    size: tuple[int, int] = (64, 64),
    colour: str = "#7c3aed",
) -> bytes:
    image = Image.new("RGB", size, colour)
    output = io.BytesIO()
    image.save(output, format=fmt)
    return output.getvalue()


def _animated_webp_bytes() -> bytes:
    frames = [
        Image.new("RGB", (32, 32), "#ef4444"),
        Image.new("RGB", (32, 32), "#3b82f6"),
    ]
    output = io.BytesIO()
    frames[0].save(
        output,
        format="WEBP",
        save_all=True,
        append_images=frames[1:],
        duration=100,
    )
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
    key: str = "manual-key-123456",
) -> Payment:
    return create_manual_payment_attempt(user.id, order.order_number, key)


def _upload_proof(
    client: FlaskClient,
    token: str,
    payment_reference: str,
    payload: bytes,
    *,
    filename: str = "receipt.png",
    content_type: str = "image/png",
    include_csrf: bool = True,
    follow_redirects: bool = True,
) -> object:
    data: dict[str, object] = {
        "proof": (io.BytesIO(payload), filename, content_type),
    }
    if include_csrf:
        data["csrf_token"] = token
    return client.post(
        f"/payments/{payment_reference}/proof",
        data=data,
        follow_redirects=follow_redirects,
    )


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


def test_manual_transfer_initiation_uses_server_total_and_displayed_details(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="manual-init@example.com")
    order = make_order(user)
    login(user.email)
    token = csrf_token(f"/orders/{order.order_number}/pay")

    pay_page = client.get(f"/orders/{order.order_number}/pay")
    assert pay_page.status_code == 200
    pay_html = pay_page.get_data(as_text=True)
    assert "Manual bank transfer" in pay_html
    assert "Create bank transfer instructions" in pay_html
    assert bank_transfer_config["BANK_TRANSFER_BANK_NAME"] in pay_html
    assert "Rp " in pay_html

    response = client.post(
        f"/orders/{order.order_number}/manual-payments",
        data={
            "csrf_token": token,
            "idempotency_key": "manual-route-key-123",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/payments/PAY-")

    payment = db.session.scalar(select(Payment))
    assert payment is not None
    assert payment.provider == PAYMENT_PROVIDER_MANUAL_TRANSFER
    assert payment.payment_method == PAYMENT_METHOD_BANK_TRANSFER
    assert payment.amount == order.total
    assert payment.currency == "IDR"
    assert payment.status == PAYMENT_STATUS_PENDING
    remaining = payment.expires_at - datetime.now(UTC)
    assert timedelta(hours=23, minutes=59) <= remaining <= timedelta(hours=24, minutes=1)

    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    html = detail.get_data(as_text=True)
    assert payment.payment_reference in html
    assert order.order_number in html
    assert bank_transfer_config["BANK_TRANSFER_BANK_NAME"] in html
    assert bank_transfer_config["BANK_TRANSFER_ACCOUNT_NAME"] in html
    assert bank_transfer_config["BANK_TRANSFER_ACCOUNT_NUMBER"] in html
    assert "Submit proof for review" in html
    assert "JPEG, PNG, WebP or PDF" in html


def test_manual_transfer_is_unavailable_without_complete_bank_details(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "BANK_TRANSFER_BANK_NAME", "")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NAME", "")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NUMBER", "")
    user = make_user(email="manual-missing-config@example.com")
    order = make_order(user)
    login(user.email)
    token = csrf_token(f"/orders/{order.order_number}/pay")

    assert manual_transfer_details() is None
    response = client.post(
        f"/orders/{order.order_number}/manual-payments",
        data={"csrf_token": token, "idempotency_key": "manual-missing-config-key"},
    )

    assert response.status_code == 503
    assert "Manual bank transfer is unavailable" in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(Payment.id))) == 0

    monkeypatch.setitem(app.config, "BANK_TRANSFER_BANK_NAME", "Configured Bank")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NAME", "")
    assert manual_transfer_details() is None


def test_manual_transfer_ttl_is_separate_from_simulated_ttl(
    app: Flask,
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(email="manual-ttl@example.com")
    order = make_order(user)
    monkeypatch.setitem(app.config, "MANUAL_TRANSFER_TTL_HOURS", 1)

    manual = _manual_payment(user, order, key="manual-ttl-key")
    simulated = create_payment_attempt(user.id, order.order_number, "simulated-ttl-key")

    manual_remaining = manual.expires_at - datetime.now(UTC)
    simulated_remaining = simulated.expires_at - datetime.now(UTC)
    assert timedelta(minutes=59) <= manual_remaining <= timedelta(minutes=61)
    assert timedelta(minutes=14) <= simulated_remaining <= timedelta(minutes=16)
    assert manual.provider == PAYMENT_PROVIDER_MANUAL_TRANSFER
    assert simulated.provider == PAYMENT_PROVIDER_SIMULATED
    assert simulated.payment_method == PAYMENT_METHOD_SIMULATED


@pytest.mark.parametrize(
    ("order_status", "payment_status", "message"),
    [
        ("cancelled", "unpaid", "cancelled"),
        ("pending", "paid", "already paid"),
        ("shipped", "unpaid", "pending or processing"),
    ],
)
def test_manual_initiation_rejects_ineligible_orders(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    order_status: str,
    payment_status: str,
    message: str,
) -> None:
    user = make_user(email=f"manual-ineligible-{order_status}-{payment_status}@example.com")
    order = make_order(user, status=order_status, payment_status=payment_status)
    login(user.email)
    token = csrf_token(f"/orders/{order.order_number}/pay")

    response = client.post(
        f"/orders/{order.order_number}/manual-payments",
        data={"csrf_token": token, "idempotency_key": "manual-ineligible-key"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert message in response.get_data(as_text=True).lower()
    assert db.session.scalar(select(func.count(Payment.id))) == 0


def test_manual_initiation_idempotency_key_returns_same_attempt(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    user = make_user(email="manual-idempotency@example.com")
    order = make_order(user)
    login(user.email)
    token = csrf_token(f"/orders/{order.order_number}/pay")
    data = {"csrf_token": token, "idempotency_key": "manual-duplicate-key"}

    first = client.post(f"/orders/{order.order_number}/manual-payments", data=data)
    second = client.post(f"/orders/{order.order_number}/manual-payments", data=data)

    assert first.status_code == 302
    assert second.status_code == 302
    assert first.headers["Location"] == second.headers["Location"]
    assert db.session.scalar(select(func.count(Payment.id))) == 1


def test_manual_payment_detail_and_proof_upload_are_owner_only(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
) -> None:
    owner = make_user(email="manual-owner@example.com")
    make_user(email="manual-other@example.com")
    order = make_order(owner)
    payment = _manual_payment(owner, order)
    login("manual-other@example.com")

    assert client.get(f"/payments/{payment.payment_reference}").status_code == 404
    response = _upload_proof(
        client,
        csrf_token("/auth/account"),
        payment.payment_reference,
        _image_bytes("PNG"),
    )
    assert response.status_code == 404
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0


@pytest.mark.parametrize(
    ("fmt", "filename", "content_type", "expected_mime", "suffix"),
    [
        ("JPEG", "receipt.jpg", "image/jpeg", "image/jpeg", ".jpg"),
        ("PNG", "receipt.png", "image/png", "image/png", ".png"),
        ("WEBP", "receipt.webp", "image/webp", "image/webp", ".webp"),
        ("PDF", "receipt.pdf", "application/pdf", "application/pdf", ".pdf"),
    ],
)
def test_customer_uploads_supported_proof_formats(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    fmt: str,
    filename: str,
    content_type: str,
    expected_mime: str,
    suffix: str,
) -> None:
    user = make_user(email=f"proof-format-{fmt.lower()}@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    payload = _pdf_bytes() if fmt == "PDF" else _image_bytes(fmt)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        payload,
        filename=filename,
        content_type=content_type,
    )

    assert response.status_code == 200
    assert "Payment proof submitted for review." in response.get_data(as_text=True)

    proof = db.session.scalar(select(PaymentProof))
    assert proof is not None
    assert proof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW
    assert proof.mime_type == expected_mime
    assert proof.file_size == len(payload)
    assert PROOF_FILENAME_PATTERN.fullmatch(proof.proof_filename)
    assert proof.proof_filename.endswith(suffix)
    stored_path = payment_proof_storage / proof.proof_filename
    assert stored_path.is_file()
    assert stored_path.read_bytes() == payload
    assert stored_path.stat().st_mode & 0o777 == 0o600
    assert payment_proof_storage.stat().st_mode & 0o777 == 0o700
    assert proof.proof_filename not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("payload", "filename", "content_type"),
    [
        (b'<svg xmlns="http://www.w3.org/2000/svg"></svg>', "proof.svg", "image/svg+xml"),
        (b"<html><body>not a receipt</body></html>", "proof.jpg", "image/jpeg"),
        (b"MZ" + b"\x00" * 128, "proof.png", "image/png"),
        (b"not a valid image or pdf", "proof.webp", "image/webp"),
        (b"%PDF-1.4\nnot a complete pdf", "proof.pdf", "application/pdf"),
        (b"", "empty.png", "image/png"),
    ],
)
def test_customer_proof_upload_rejects_invalid_or_spoofed_files(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    payload: bytes,
    filename: str,
    content_type: str,
) -> None:
    user = make_user(email=f"proof-invalid-{filename.replace('.', '-')}@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        payload,
        filename=filename,
        content_type=content_type,
    )

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0
    assert not payment_proof_storage.exists() or not list(payment_proof_storage.iterdir())


def test_customer_proof_upload_rejects_animated_images(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-animated@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _animated_webp_bytes(),
        filename="animated.webp",
        content_type="image/webp",
    )

    assert response.status_code == 200
    assert "Animated proof images are not supported." in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0


def test_customer_proof_upload_rejects_default_five_mb_oversize(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-default-size@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        b"\x00" * (5 * 1024 * 1024 + 1),
        filename="too-large.png",
    )

    assert response.status_code == 200
    assert "maximum file size" in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0
    assert not payment_proof_storage.exists() or not list(payment_proof_storage.iterdir())


def test_customer_proof_upload_rejects_oversize_and_traversal_names(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(email="proof-size-and-name@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")
    monkeypatch.setitem(app.config, "PAYMENT_PROOF_MAX_BYTES", 128)

    oversize = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG", size=(256, 256)),
    )
    assert oversize.status_code == 200
    assert "maximum file size" in oversize.get_data(as_text=True)
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0

    monkeypatch.setitem(app.config, "PAYMENT_PROOF_MAX_BYTES", 5 * 1024 * 1024)
    traversal = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
        filename="../../evil.png",
    )
    assert traversal.status_code == 200
    proof = db.session.scalar(select(PaymentProof))
    assert proof is not None
    assert PROOF_FILENAME_PATTERN.fullmatch(proof.proof_filename)
    assert "evil" not in proof.proof_filename
    assert (payment_proof_storage / proof.proof_filename).is_file()
    assert not (payment_proof_storage.parent / "evil.png").exists()


def test_duplicate_pending_proof_is_rejected(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-duplicate-pending@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")
    first = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
        filename="first.png",
    )
    assert first.status_code == 200

    second = _upload_proof(
        client,
        csrf_token("/auth/account"),
        payment.payment_reference,
        _image_bytes("JPEG"),
        filename="second.jpg",
        content_type="image/jpeg",
    )

    assert second.status_code == 200
    assert "already awaiting review" in second.get_data(as_text=True)
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 1
    assert len(list(payment_proof_storage.iterdir())) == 1


def test_upload_rejected_after_manual_payment_deadline(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-expired-upload@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    payment.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.session.commit()
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
    )

    assert response.status_code == 200
    assert "expired" in response.get_data(as_text=True).lower()
    refreshed = db.session.get(Payment, payment.id)
    assert refreshed is not None
    assert refreshed.status == PAYMENT_STATUS_EXPIRED
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0


def test_database_failure_removes_new_proof_file(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(email="proof-db-failure@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    def _fail_commit() -> None:
        raise PaymentProofError("Simulated database failure.")

    monkeypatch.setattr("app.services.payment_proofs._commit_or_raise", _fail_commit)
    response = _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
    )

    assert response.status_code == 200
    assert "Simulated database failure." in response.get_data(as_text=True)
    db.session.rollback()
    assert db.session.scalar(select(func.count(PaymentProof.id))) == 0
    assert not payment_proof_storage.exists() or not list(payment_proof_storage.iterdir())


def test_rejection_preserves_history_and_allows_replacement(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-replacement@example.com")
    admin = make_user(email="proof-replacement-admin@example.com", role=ROLE_ADMIN)
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")

    _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
        filename="first.png",
    )
    first = db.session.scalar(select(PaymentProof))
    assert first is not None
    first_filename = first.proof_filename

    result = reject_payment_proof(first.id, admin.id, "Receipt is too blurry.")
    assert "rejected" in result.message.lower()

    detail = client.get(f"/payments/{payment.payment_reference}")
    assert detail.status_code == 200
    assert "Receipt is too blurry." in detail.get_data(as_text=True)
    assert "Rejected" in detail.get_data(as_text=True)

    second = _upload_proof(
        client,
        csrf_token("/auth/account"),
        payment.payment_reference,
        _image_bytes("JPEG"),
        filename="second.jpg",
        content_type="image/jpeg",
    )
    assert second.status_code == 200
    assert "Payment proof submitted for review." in second.get_data(as_text=True)

    proofs = db.session.scalars(select(PaymentProof).order_by(PaymentProof.id)).all()
    assert [proof.status for proof in proofs] == [
        PAYMENT_PROOF_STATUS_REJECTED,
        PAYMENT_PROOF_STATUS_PENDING_REVIEW,
    ]
    assert (payment_proof_storage / first_filename).is_file()
    assert len(list(payment_proof_storage.iterdir())) == 2


def test_payment_detail_get_does_not_expire_manual_payment(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-get-no-mutation@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")
    _upload_proof(client, token, payment.payment_reference, _image_bytes("PNG"))
    proof = db.session.scalar(select(PaymentProof))
    assert proof is not None
    payment.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.session.commit()

    response = client.get(f"/payments/{payment.payment_reference}")

    assert response.status_code == 200
    assert "The payment deadline has passed" in response.get_data(as_text=True)
    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_PENDING
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_PENDING_REVIEW


def test_payment_expiration_cancels_pending_proof(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-expire-payment@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")
    _upload_proof(client, token, payment.payment_reference, _image_bytes("PNG"))
    proof = db.session.scalar(select(PaymentProof))
    assert proof is not None

    expire_payment_attempt(
        payment.payment_reference,
        now=payment.expires_at + timedelta(seconds=1),
    )

    db.session.expire_all()
    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_EXPIRED
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_CANCELLED


def test_order_cancellation_expires_manual_payment_and_cancels_proof(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    bank_transfer_config: dict[str, str],
    payment_proof_storage: Path,
) -> None:
    user = make_user(email="proof-cancel-order@example.com")
    order = make_order(user)
    payment = _manual_payment(user, order)
    login(user.email)
    token = csrf_token(f"/payments/{payment.payment_reference}")
    _upload_proof(
        client,
        token,
        payment.payment_reference,
        _image_bytes("PNG"),
    )
    proof = db.session.scalar(select(PaymentProof))
    assert proof is not None

    cancel_customer_order(user.id, order.order_number, reason="Customer cancelled")

    refreshed_payment = db.session.get(Payment, payment.id)
    refreshed_proof = db.session.get(PaymentProof, proof.id)
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_payment is not None
    assert refreshed_payment.status == PAYMENT_STATUS_EXPIRED
    assert refreshed_proof is not None
    assert refreshed_proof.status == PAYMENT_PROOF_STATUS_CANCELLED
    assert refreshed_order is not None
    assert refreshed_order.status == "cancelled"
    assert refreshed_order.payment_status == "unpaid"
