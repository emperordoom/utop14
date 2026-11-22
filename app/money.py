"""Canonical Indonesian Rupiah (IDR) whole-rupiah validation helpers.

UTOP14 operates exclusively in Indonesian Rupiah (IDR) with whole-rupiah
amounts.  Database columns remain ``Numeric(12, 2)``, so validated internal
``Decimal`` values are normalized to exact ``.00`` scale without ever rounding,
truncating, or converting through binary floating point.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Final

CURRENCY_IDR: Final = "IDR"
RUPIAH_SCALE: Final = Decimal("0.01")
MAX_RUPIAH_AMOUNT: Final = Decimal("9999999999.00")
# Hard ceiling even when ``maximum=None`` (18 whole digits) so extreme Decimal
# exponents such as ``Decimal("1e5000")`` are rejected as MoneyValidationError
# before any integer or string conversion can occur.
MAX_UNBOUNDED_RUPIAH_AMOUNT: Final = Decimal("999999999999999999.00")
_MAX_SAFE_ADJUSTED_EXPONENT: Final = 17

_PRICE_INPUT_PATTERN: Final = re.compile(r"\A[0-9]{1,10}(?:\.00)?\Z")
_FRACTIONAL_PRICE_PATTERN: Final = re.compile(r"\A[0-9]{1,10}\.[0-9]+\Z")


class MoneyValidationError(ValueError):
    """Raised when a monetary value violates UTOP14 whole-rupiah invariants."""


def _has_nonzero_fraction(value: Decimal) -> bool:
    """Return True when a finite Decimal has any non-zero fractional digit."""
    _, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int) or exponent >= 0:
        return False
    fractional_count = min(-exponent, len(digits))
    return any(digit != 0 for digit in digits[-fractional_count:])


def validate_whole_rupiah(
    value: object,
    *,
    label: str = "Amount",
    allow_zero: bool = True,
    maximum: Decimal | None = MAX_RUPIAH_AMOUNT,
) -> Decimal:
    """Validate an internal ``Decimal`` value as an exact whole-rupiah amount.

    Args:
        value: Internal monetary value. Must already be a ``Decimal``; ``float``,
            ``bool``, ``int``, ``str``, and ``None`` are rejected with
            ``TypeError`` so callers cannot silently introduce imprecise types.
        label: Human-readable field name used in error messages.
        allow_zero: Whether ``Decimal("0.00")`` is accepted. Pass ``False`` for
            strictly positive payable amounts.
        maximum: Optional inclusive upper bound. Defaults to the maximum
            whole-rupiah value representable in ``Numeric(12, 2)``.

    Returns:
        An exact ``Decimal`` normalized to two zero decimal places (``.00``).

    Raises:
        TypeError: If ``value`` is not a ``Decimal``.
        MoneyValidationError: If ``value`` is non-finite, negative, zero when
            disallowed, has any non-zero fractional component, or exceeds
            ``maximum``.
    """
    if not isinstance(value, Decimal):
        raise TypeError(f"{label} must be a Decimal value.")
    if not value.is_finite():
        raise MoneyValidationError(f"{label} must be a finite whole rupiah amount.")
    if value < 0:
        raise MoneyValidationError(f"{label} must be a non-negative whole rupiah amount.")
    if not allow_zero and value == 0:
        raise MoneyValidationError(f"{label} must be a positive whole rupiah amount.")
    if _has_nonzero_fraction(value):
        raise MoneyValidationError(
            f"{label} must be a whole rupiah amount without fractional decimals."
        )
    effective_maximum = MAX_UNBOUNDED_RUPIAH_AMOUNT if maximum is None else maximum
    if (value != 0 and value.adjusted() > _MAX_SAFE_ADJUSTED_EXPONENT) or value > effective_maximum:
        raise MoneyValidationError(f"{label} exceeds the maximum allowed rupiah amount.")

    return Decimal(f"{int(value)}.00")


def parse_whole_rupiah(
    value: object,
    *,
    label: str = "Price",
    allow_zero: bool = True,
    maximum: Decimal | None = MAX_RUPIAH_AMOUNT,
) -> Decimal:
    """Parse external form/service input directly into a validated whole-rupiah Decimal.

    Accepts integer strings (e.g. ``"149000"``) and exact zero-decimal strings
    (e.g. ``"149000.00"``), as well as ``Decimal`` and non-bool ``int`` values.
    Rejects non-zero fractional amounts (e.g. ``"149000.50"``, ``"149000.01"``),
    booleans, floats, ``None``, and malformed input without ever using ``float``.
    """
    if isinstance(value, Decimal):
        return validate_whole_rupiah(
            value,
            label=label,
            allow_zero=allow_zero,
            maximum=maximum,
        )
    if isinstance(value, bool) or value is None or isinstance(value, float):
        raise MoneyValidationError(
            f"{label} must be a non-negative whole rupiah amount (for example 149000)."
        )
    if isinstance(value, int):
        return validate_whole_rupiah(
            Decimal(value),
            label=label,
            allow_zero=allow_zero,
            maximum=maximum,
        )
    if not isinstance(value, str):
        raise MoneyValidationError(
            f"{label} must be a non-negative whole rupiah amount (for example 149000)."
        )

    raw = value.strip(" ")
    if not _PRICE_INPUT_PATTERN.fullmatch(raw):
        if _FRACTIONAL_PRICE_PATTERN.fullmatch(raw):
            raise MoneyValidationError(
                f"{label} must be a whole rupiah amount without fractional decimals "
                "(for example 149000 or 149000.00)."
            )
        raise MoneyValidationError(
            f"{label} must be a non-negative whole rupiah amount (for example 149000 or 149000.00)."
        )
    try:
        parsed = Decimal(raw)
    except InvalidOperation as exc:
        raise MoneyValidationError(f"{label} must be a valid whole rupiah amount.") from exc

    return validate_whole_rupiah(
        parsed,
        label=label,
        allow_zero=allow_zero,
        maximum=maximum,
    )


def whole_rupiah_to_int(
    value: object,
    *,
    label: str = "Amount",
    allow_zero: bool = True,
    maximum: Decimal | None = MAX_RUPIAH_AMOUNT,
) -> int:
    """Convert a validated whole-rupiah ``Decimal`` to an exact Python ``int``."""
    validated = validate_whole_rupiah(
        value,
        label=label,
        allow_zero=allow_zero,
        maximum=maximum,
    )
    return int(validated)
