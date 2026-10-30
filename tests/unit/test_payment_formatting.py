"""Unit tests for Indonesian Rupiah payment formatting."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.formatting import format_idr


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (Decimal("75.00"), "Rp 75"),
        (Decimal("87.00"), "Rp 87"),
        (Decimal("12.00"), "Rp 12"),
        (Decimal("0.00"), "Rp 0"),
        (Decimal("1234.50"), "Rp 1.234,50"),
        (Decimal("1000000.00"), "Rp 1.000.000"),
    ],
)
def test_format_idr_uses_indonesian_separators(amount: Decimal, expected: str) -> None:
    assert format_idr(amount) == expected


def test_format_idr_rejects_floating_point_values() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        format_idr(75.0)  # type: ignore[arg-type]
