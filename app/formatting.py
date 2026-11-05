"""Canonical formatting helpers for UTOP14."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal


def format_utc(
    value: datetime,
    fmt: str = "%d %b %Y, %H:%M:%S UTC",
) -> str:
    """Render a timezone-aware instant in UTC with a truthful UTC label.

    PostgreSQL ``timestamptz`` values are returned in the session timezone, so
    callers must not assume an aware datetime is already UTC.  Naive datetimes
    are rejected rather than silently interpreted as UTC.
    """
    if not isinstance(value, datetime):
        raise TypeError("format_utc expects a datetime value")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("format_utc requires a timezone-aware datetime")
    if not isinstance(fmt, str) or not fmt:
        raise TypeError("format_utc expects a non-empty format string")
    return value.astimezone(UTC).strftime(fmt)


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
