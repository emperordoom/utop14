"""Unit tests for UTC timestamp formatting."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from app.formatting import format_utc


def test_format_utc_converts_jakarta_instant_to_utc() -> None:
    value = datetime(2026, 1, 1, 7, 0, 0, tzinfo=ZoneInfo("Asia/Jakarta"))

    assert format_utc(value) == "01 Jan 2026, 00:00:00 UTC"


def test_format_utc_keeps_utc_instant_unchanged() -> None:
    value = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)

    assert format_utc(value) == "01 Jan 2026, 00:00:00 UTC"


def test_format_utc_supports_an_explicit_format() -> None:
    value = datetime(2026, 1, 1, 7, 0, 0, tzinfo=ZoneInfo("Asia/Jakarta"))

    assert format_utc(value, "%d %b %Y, %H:%M") == "01 Jan 2026, 00:00"


def test_format_utc_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        format_utc(datetime(2026, 1, 1, 0, 0, 0))


def test_format_utc_rejects_non_datetime() -> None:
    with pytest.raises(TypeError, match="datetime"):
        format_utc("2026-01-01T00:00:00+00:00")  # type: ignore[arg-type]


def test_format_utc_rejects_empty_format() -> None:
    with pytest.raises(TypeError, match="format"):
        format_utc(datetime(2026, 1, 1, tzinfo=UTC), "")
