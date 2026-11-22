"""Canonical formatting helpers for UTOP14."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from app.money import CURRENCY_IDR, whole_rupiah_to_int


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
    """Format a validated whole-rupiah Decimal amount as Indonesian Rupiah.

    Preserves the canonical ``Rp 149.000`` display format (with space and dot
    thousands separator, no decimal digits). Non-Decimal, non-finite, negative,
    and fractional values are rejected instead of silently rounded or disguised.
    """
    whole_amount = whole_rupiah_to_int(
        value,
        label="Amount",
        allow_zero=True,
        maximum=None,
    )
    return f"Rp {whole_amount:,}".replace(",", ".")


def format_payment_amount(amount: Decimal, currency: str | None) -> str:
    """Format a payment amount as IDR only when ``currency`` is strictly ``IDR``.

    Non-IDR payments never use ``format_idr`` or the ``Rp`` prefix. They return
    a clear fail-closed message so historical records stay inspectable without
    misrepresenting non-IDR amounts as Rupiah.
    """
    if currency != CURRENCY_IDR:
        code = currency.strip() if isinstance(currency, str) and currency.strip() else "unknown"
        return f"Unsupported currency ({code}) — amount unavailable"
    return format_idr(amount)
