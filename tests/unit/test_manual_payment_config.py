"""Unit tests for manual-transfer configuration and proof filename policy."""

from __future__ import annotations

from pathlib import Path

import pytest
from flask import Flask

from app import create_app
from app.config import PROJECT_ROOT, ConfigurationError
from app.services.payments import manual_transfer_details
from app.services.proof_storage import ProofValidationError, validate_proof_filename


def test_manual_transfer_details_require_all_fields(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "BANK_TRANSFER_BANK_NAME", "")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NAME", "")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NUMBER", "")
    assert manual_transfer_details() is None

    monkeypatch.setitem(app.config, "BANK_TRANSFER_BANK_NAME", "Test Bank")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NAME", "Test Account")
    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NUMBER", "123")
    details = manual_transfer_details()
    assert details is not None
    assert details.bank_name == "Test Bank"

    monkeypatch.setitem(app.config, "BANK_TRANSFER_ACCOUNT_NUMBER", "")
    assert manual_transfer_details() is None


def test_proof_storage_defaults_are_private_and_bounded() -> None:
    app = create_app("testing")
    storage = Path(app.config["PAYMENT_PROOF_STORAGE_PATH"]).resolve()
    static_root = Path(app.static_folder).resolve()
    app_root = Path(app.root_path).resolve()

    assert app.config["PAYMENT_PROOF_MAX_BYTES"] == 5 * 1024 * 1024
    assert app.config["PAYMENT_PROOF_MAX_DIMENSION"] == 4096
    assert storage != static_root
    assert static_root not in storage.parents
    assert storage != app_root
    assert app_root not in storage.parents


def test_proof_storage_inside_source_tree_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="outside"):
        create_app(
            "testing",
            {"PAYMENT_PROOF_STORAGE_PATH": str(PROJECT_ROOT / "app" / "static" / "proofs")},
        )


@pytest.mark.parametrize("value", [0, -1, 1.5, "24", None, True])
def test_invalid_manual_transfer_ttl_is_rejected(value: object) -> None:
    with pytest.raises(ConfigurationError, match="MANUAL_TRANSFER_TTL_HOURS"):
        create_app("testing", {"MANUAL_TRANSFER_TTL_HOURS": value})


def test_valid_manual_transfer_ttl_is_loaded() -> None:
    app = create_app("testing", {"MANUAL_TRANSFER_TTL_HOURS": 48})
    assert app.config["MANUAL_TRANSFER_TTL_HOURS"] == 48


def test_generated_proof_filename_is_accepted() -> None:
    filename = f"{'a' * 32}.pdf"
    assert validate_proof_filename(filename) == filename


@pytest.mark.parametrize(
    "filename",
    [
        "../proof.pdf",
        f"{'a' * 32}.exe",
        f"{'a' * 31}.png",
        "",
        None,
        42,
    ],
)
def test_unsafe_proof_filename_is_rejected(filename: object) -> None:
    with pytest.raises(ProofValidationError, match="Invalid payment proof filename"):
        validate_proof_filename(filename)
