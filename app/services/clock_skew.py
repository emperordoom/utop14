"""Database clock-skew diagnostics.

Security-event retention compares PostgreSQL-generated event timestamps with a
PostgreSQL-generated cutoff.  Rate limiting, payment expiry and admin filter
state still use application time, so every application node must keep its clock
synchronised (NTP).  This module reports the difference between application UTC
time and the database clock without ever changing either clock.

The diagnostic is advisory: an unavailable database or a skewed clock must not
turn a normal request or a retention run into a failure.  Callers receive
``None`` when the database time cannot be read, and log a warning when the
absolute skew exceeds the configured threshold.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from flask import current_app
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

_DEFAULT_THRESHOLD_SECONDS = 120


@dataclass(frozen=True, slots=True)
class ClockSkewResult:
    """Application/database clock comparison for one observation."""

    app_time: datetime
    database_time: datetime
    skew_seconds: float
    threshold_seconds: int

    @property
    def exceeded(self) -> bool:
        return abs(self.skew_seconds) > self.threshold_seconds


def clock_skew_threshold_seconds() -> int:
    """Return the validated warning threshold, falling back safely."""
    value = current_app.config.get("CLOCK_SKEW_WARNING_SECONDS")
    if type(value) is int and 1 <= value <= 86_400:
        return value
    return _DEFAULT_THRESHOLD_SECONDS


def check_clock_skew(engine: Engine) -> ClockSkewResult | None:
    """Compare application UTC time with ``SELECT now()`` on ``engine``.

    Returns ``None`` when the database clock cannot be read.  Never raises for
    an unavailable database and never logs a connection string or credential.
    """
    threshold = clock_skew_threshold_seconds()
    app_time = datetime.now(UTC)
    try:
        with engine.connect() as connection:
            database_time = connection.execute(text("SELECT now()")).scalar_one()
    except SQLAlchemyError:
        current_app.logger.warning("clock_skew_diagnostic_unavailable")
        return None
    except Exception:  # pragma: no cover - defensive: diagnostics are advisory
        current_app.logger.warning("clock_skew_diagnostic_failed")
        return None

    if not isinstance(database_time, datetime):
        current_app.logger.warning("clock_skew_diagnostic_invalid_result")
        return None
    if database_time.tzinfo is None:
        database_time = database_time.replace(tzinfo=UTC)
    database_time = database_time.astimezone(UTC)

    skew_seconds = (app_time - database_time).total_seconds()
    result = ClockSkewResult(
        app_time=app_time,
        database_time=database_time,
        skew_seconds=skew_seconds,
        threshold_seconds=threshold,
    )
    if result.exceeded:
        # Only numeric values are logged; never the DSN or role password.
        current_app.logger.warning(
            "clock_skew_exceeded skew_seconds=%.1f threshold_seconds=%d",
            skew_seconds,
            threshold,
        )
    return result
