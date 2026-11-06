"""Regression tests for the advisory database clock-skew diagnostic."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy.exc import OperationalError

from app import create_app
from app.config import ConfigurationError
from app.services.clock_skew import ClockSkewResult, check_clock_skew


class _Result:
    def __init__(self, value: object):
        self.value = value

    def scalar_one(self) -> object:
        return self.value


class _Connection:
    def __init__(self, value: object = None, error: Exception | None = None):
        self.value = value
        self.error = error

    def execute(self, _statement: object) -> _Result:
        if self.error is not None:
            raise self.error
        return _Result(self.value)

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class _Engine:
    def __init__(self, value: object = None, error: Exception | None = None):
        self.value = value
        self.error = error

    def connect(self) -> _Connection:
        if self.error is not None:
            raise self.error
        return _Connection(self.value)


def _capture_warnings(app: Flask, operation):
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    previous_level = app.logger.level
    previous_disabled = app.logger.disabled
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.WARNING)
    app.logger.disabled = False
    try:
        result = operation()
    finally:
        app.logger.removeHandler(handler)
        app.logger.setLevel(previous_level)
        app.logger.disabled = previous_disabled
    return result, [record.getMessage() for record in records]


def test_positive_skew_warns(app: Flask) -> None:
    app.config["CLOCK_SKEW_WARNING_SECONDS"] = 120
    db_time = datetime.now(UTC) - timedelta(seconds=121)
    result, messages = _capture_warnings(app, lambda: check_clock_skew(_Engine(db_time)))

    assert result is not None
    assert result.exceeded is True
    assert 120.9 < result.skew_seconds < 121.1
    assert any("clock_skew_exceeded" in message for message in messages)


def test_negative_skew_warns(app: Flask) -> None:
    app.config["CLOCK_SKEW_WARNING_SECONDS"] = 120
    db_time = datetime.now(UTC) + timedelta(seconds=121)
    result, messages = _capture_warnings(app, lambda: check_clock_skew(_Engine(db_time)))

    assert result is not None
    assert result.exceeded is True
    assert -121.1 < result.skew_seconds < -120.9
    assert any("clock_skew_exceeded" in message for message in messages)


@pytest.mark.parametrize(
    ("skew_seconds", "exceeded"),
    [
        (120.0, False),
        (-120.0, False),
        (120.0001, True),
        (-120.0001, True),
    ],
)
def test_threshold_boundary(skew_seconds: float, exceeded: bool) -> None:
    now = datetime.now(UTC)
    result = ClockSkewResult(
        app_time=now,
        database_time=now,
        skew_seconds=skew_seconds,
        threshold_seconds=120,
    )

    assert result.exceeded is exceeded


@pytest.mark.parametrize("value", [0, -1, 86401, True, "120", 120.5, None])
def test_invalid_threshold_rejected(app: Flask, value: object) -> None:
    with pytest.raises(ConfigurationError, match="CLOCK_SKEW_WARNING_SECONDS"):
        create_app(
            "testing",
            {
                "SQLALCHEMY_DATABASE_URI": app.config["SQLALCHEMY_DATABASE_URI"],
                "SECURITY_EVENT_HASH_KEY": app.config["SECURITY_EVENT_HASH_KEY"],
                "CLOCK_SKEW_WARNING_SECONDS": value,
            },
        )


def test_database_unavailable_is_nonfatal(app: Flask) -> None:
    error = OperationalError("sensitive connection detail", {}, Exception())
    result, messages = _capture_warnings(
        app,
        lambda: check_clock_skew(_Engine(error=error)),
    )

    assert result is None
    assert any("clock_skew_diagnostic_unavailable" in message for message in messages)
    assert all("sensitive connection detail" not in message for message in messages)


def test_cli_check_clock_unavailable_is_nonfatal(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.cli as cli_module

    monkeypatch.setattr(cli_module, "check_clock_skew", lambda _engine: None)

    result = app.test_cli_runner().invoke(
        args=["security-event-retention", "check-clock"],
    )

    assert result.exit_code == 0
    assert "diagnostic unavailable" in result.output


def test_naive_database_timestamp_is_normalized(app: Flask) -> None:
    db_time = datetime.now(UTC).replace(tzinfo=None)
    result = check_clock_skew(_Engine(db_time))

    assert result is not None
    assert result.database_time.tzinfo is not None
    assert result.database_time.utcoffset() == timedelta(0)
