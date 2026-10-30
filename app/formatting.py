"""Canonical Indonesian Rupiah money formatting for UTOP14."""

from __future__ import annotations

from decimal import Decimal


def format_idr(value: Decimal) -> str:
    """Format a Decimal amount as Indonesian Rupiah.

    Whole amounts omit decimals; fractional amounts use an Indonesian comma
    decimal separator. Thousands use dots. Values must already be Decimal so
    callers cannot accidentally introduce binary floating-point rounding.
    """
    if not isinstance(value, Decimal):
        raise TypeError("format_idr expects a Decimal value")

    if value == value.to_integral_value():
        return f"Rp {value:,.0f}".replace(",", ".")
    return f"Rp {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
