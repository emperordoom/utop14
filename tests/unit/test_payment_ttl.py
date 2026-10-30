"""Unit tests for the defensive payment TTL helper."""

from __future__ import annotations

import pytest
from flask import Flask

from app.services.payments import payment_attempt_ttl_minutes

DEFAULT_TTL_MINUTES = 15


@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        -15,
        True,
        False,
        15.0,
        15.9,
        "15",
        "15.0",
        "15.9",
        "",
        "not-a-number",
        None,
    ],
)
def test_invalid_ttl_falls_back_to_default(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    monkeypatch.setitem(app.config, "PAYMENT_ATTEMPT_TTL_MINUTES", value)

    assert payment_attempt_ttl_minutes() == DEFAULT_TTL_MINUTES


@pytest.mark.parametrize("value", [1, 15, 30, 120])
def test_positive_integer_ttl_is_returned(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    value: int,
) -> None:
    monkeypatch.setitem(app.config, "PAYMENT_ATTEMPT_TTL_MINUTES", value)

    assert payment_attempt_ttl_minutes() == value


def test_missing_ttl_falls_back_to_default(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delitem(app.config, "PAYMENT_ATTEMPT_TTL_MINUTES", raising=False)

    assert payment_attempt_ttl_minutes() == DEFAULT_TTL_MINUTES
