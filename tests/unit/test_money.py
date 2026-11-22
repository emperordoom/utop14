"""Unit tests for canonical whole-rupiah validation and conversion helpers."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.money import (
    MAX_RUPIAH_AMOUNT,
    MAX_UNBOUNDED_RUPIAH_AMOUNT,
    MoneyValidationError,
    parse_whole_rupiah,
    validate_whole_rupiah,
    whole_rupiah_to_int,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (Decimal("0"), Decimal("0.00")),
        (Decimal("0.00"), Decimal("0.00")),
        (Decimal("-0.00"), Decimal("0.00")),
        (Decimal("149000"), Decimal("149000.00")),
        (Decimal("149000.00"), Decimal("149000.00")),
        (Decimal("149000.000"), Decimal("149000.00")),
        (Decimal("149000.0000"), Decimal("149000.00")),
        (MAX_RUPIAH_AMOUNT, MAX_RUPIAH_AMOUNT),
    ],
)
def test_validate_whole_rupiah_accepts_exact_whole_decimals(
    raw: Decimal,
    expected: Decimal,
) -> None:
    validated = validate_whole_rupiah(raw)
    assert validated == expected
    assert validated.as_tuple().exponent == -2


def test_validate_whole_rupiah_enforces_strictly_positive_when_required() -> None:
    with pytest.raises(MoneyValidationError, match="positive"):
        validate_whole_rupiah(Decimal("0.00"), allow_zero=False)


@pytest.mark.parametrize(
    "invalid",
    [
        Decimal("149000.50"),
        Decimal("149000.01"),
        Decimal("0.01"),
        Decimal("149000.000000000000000000000000000001"),
        Decimal("-1.00"),
        Decimal("-0.01"),
        Decimal("NaN"),
        Decimal("sNaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
        Decimal("10000000000.00"),
    ],
)
def test_validate_whole_rupiah_rejects_invalid_decimals(invalid: Decimal) -> None:
    with pytest.raises(MoneyValidationError):
        validate_whole_rupiah(invalid)


@pytest.mark.parametrize("bad_type", [149000.0, 149000.5, True, False, None, 149000, "149000"])
def test_validate_whole_rupiah_rejects_non_decimal_types(bad_type: object) -> None:
    with pytest.raises(TypeError, match="Decimal"):
        validate_whole_rupiah(bad_type)


def test_whole_rupiah_to_int_returns_exact_integer() -> None:
    result = whole_rupiah_to_int(Decimal("149000.00"))
    assert type(result) is int
    assert result == 149000
    assert whole_rupiah_to_int(Decimal("0.00")) == 0


@pytest.mark.parametrize(
    ("invalid", "exc_type"),
    [
        (Decimal("149000.50"), MoneyValidationError),
        (Decimal("149000.01"), MoneyValidationError),
        (Decimal("-100.00"), MoneyValidationError),
        (Decimal("NaN"), MoneyValidationError),
        (Decimal("Infinity"), MoneyValidationError),
        (Decimal("-Infinity"), MoneyValidationError),
        (149000.0, TypeError),
        (149000.5, TypeError),
        (True, TypeError),
        (False, TypeError),
        (None, TypeError),
    ],
)
def test_whole_rupiah_to_int_rejects_fractional_and_invalid_values(
    invalid: object,
    exc_type: type[Exception],
) -> None:
    with pytest.raises(exc_type):
        whole_rupiah_to_int(invalid)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("149000", Decimal("149000.00")),
        ("149000.00", Decimal("149000.00")),
        (" 329000 ", Decimal("329000.00")),
        ("0", Decimal("0.00")),
        ("0.00", Decimal("0.00")),
        (Decimal("149000.00"), Decimal("149000.00")),
        (149000, Decimal("149000.00")),
    ],
)
def test_parse_whole_rupiah_accepts_valid_inputs(raw: object, expected: Decimal) -> None:
    assert parse_whole_rupiah(raw) == expected


@pytest.mark.parametrize(
    "extreme",
    [
        Decimal("1e5000"),
        Decimal("1e1000000"),
        Decimal("1e18"),
        Decimal("1e-5000"),
    ],
)
def test_validate_and_convert_reject_extreme_exponents_as_money_error(
    extreme: Decimal,
) -> None:
    with pytest.raises(MoneyValidationError):
        validate_whole_rupiah(extreme, maximum=None)
    with pytest.raises(MoneyValidationError):
        whole_rupiah_to_int(extreme, maximum=None)


def test_validate_whole_rupiah_caps_unbounded_and_custom_extreme_maximum() -> None:
    assert (
        validate_whole_rupiah(MAX_UNBOUNDED_RUPIAH_AMOUNT, maximum=None)
        == MAX_UNBOUNDED_RUPIAH_AMOUNT
    )
    with pytest.raises(MoneyValidationError):
        validate_whole_rupiah(Decimal("1e5000"), maximum=Decimal("1e5000"))


@pytest.mark.parametrize(
    "invalid",
    [
        "149000.0",
        "149000.50",
        "149000.01",
        "0.01",
        "-1",
        "-149000.00",
        "\u0661\u0664\u0669\u0660\u0660\u0660",
        "\u06f1\u06f4\u06f9\u06f0\u06f0\u06f0",
        "149 000",
        "149000\n",
        "\t149000",
        "\u00a0149000",
        "+149000",
        "149000.",
        "149_000",
        "149,000",
        "1e5",
        "abc",
        "",
        149000.0,
        True,
        False,
        None,
        Decimal("149000.50"),
        Decimal("NaN"),
        Decimal("Infinity"),
    ],
)
def test_parse_whole_rupiah_rejects_fractional_and_malformed_inputs(invalid: object) -> None:
    with pytest.raises(MoneyValidationError):
        parse_whole_rupiah(invalid)
