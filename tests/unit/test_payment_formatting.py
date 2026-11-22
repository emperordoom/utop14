"""Unit tests for Indonesian Rupiah payment formatting."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.formatting import format_idr, format_payment_amount
from app.money import MoneyValidationError


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (Decimal("149000.00"), "Rp 149.000"),
        (Decimal("329000.00"), "Rp 329.000"),
        (Decimal("279000.00"), "Rp 279.000"),
        (Decimal("119000.00"), "Rp 119.000"),
        (Decimal("15000.00"), "Rp 15.000"),
        (Decimal("350000.00"), "Rp 350.000"),
        (Decimal("0.00"), "Rp 0"),
        (Decimal("1000000.00"), "Rp 1.000.000"),
    ],
)
def test_format_idr_uses_indonesian_separators(amount: Decimal, expected: str) -> None:
    assert format_idr(amount) == expected


@pytest.mark.parametrize(
    "invalid",
    [
        Decimal("1234.50"),
        Decimal("149000.01"),
        Decimal("-1.00"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("1e5000"),
        Decimal("1e1000000"),
        Decimal("1e18"),
        Decimal("1e-5000"),
    ],
)
def test_format_idr_rejects_invalid_and_fractional_values(invalid: Decimal) -> None:
    with pytest.raises(MoneyValidationError):
        format_idr(invalid)


def test_format_idr_rejects_floating_point_values() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        format_idr(75.0)  # type: ignore[arg-type]


def test_format_payment_amount_formats_idr_and_fails_closed_for_non_idr() -> None:
    assert format_payment_amount(Decimal("149000.00"), "IDR") == "Rp 149.000"

    for currency, expected_code in [
        ("USD", "USD"),
        ("EUR", "EUR"),
        ("idr", "idr"),
        ("", "unknown"),
        (None, "unknown"),
    ]:
        rendered = format_payment_amount(Decimal("100.00"), currency)
        assert "Rp" not in rendered
        assert f"Unsupported currency ({expected_code})" in rendered
        assert "amount unavailable" in rendered

    fractional_non_idr = format_payment_amount(Decimal("100.50"), "USD")
    assert "Rp" not in fractional_non_idr
    assert "Unsupported currency (USD)" in fractional_non_idr
