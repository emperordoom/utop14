"""Security-event investigative holds and bounded retention orchestration."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from flask import current_app
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.extensions import db
from app.models.security_event import SecurityEvent
from app.models.security_event_retention import (
    RETENTION_SCOPE_FAILURE,
    RETENTION_SCOPE_SUCCESS,
    RETENTION_STATUS_FAILED,
    RETENTION_STATUS_PARTIAL,
    SecurityEventRetentionHold,
)

_ADVISORY_LOCK_KEY = 0x55544F50313433  # "UTOP143"
_EVENT_LOCK_NAMESPACE = 7381


class RetentionError(Exception):
    """Base error for retention and investigative hold operations."""


class RetentionValidationError(RetentionError):
    """Raised when a hold or retention request is invalid."""


class RetentionHoldExists(RetentionError):
    """Raised when an event already has an active investigative hold."""


class RetentionLocked(RetentionError):
    """Raised when another retention run owns the advisory lock."""


class RetentionRunError(RetentionError):
    """Raised when a retention batch or run log operation fails."""


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    success_days: int
    failure_days: int
    hold_max_days: int
    batch_size: int
    max_batch_size: int
    max_batches: int


@dataclass(frozen=True, slots=True)
class RetentionRunSummary:
    run_id: str
    deleted_count: int
    batch_count: int
    status: str


def retention_policy() -> RetentionPolicy:
    """Resolve and validate the configured retention policy."""
    policy = RetentionPolicy(
        success_days=current_app.config["SECURITY_EVENT_SUCCESS_RETENTION_DAYS"],
        failure_days=current_app.config["SECURITY_EVENT_FAILURE_RETENTION_DAYS"],
        hold_max_days=current_app.config["SECURITY_EVENT_RETENTION_HOLD_MAX_DAYS"],
        batch_size=current_app.config["SECURITY_EVENT_RETENTION_BATCH_SIZE"],
        max_batch_size=current_app.config["SECURITY_EVENT_RETENTION_MAX_BATCH_SIZE"],
        max_batches=current_app.config["SECURITY_EVENT_RETENTION_MAX_BATCHES"],
    )
    if (
        type(policy.success_days) is not int
        or type(policy.failure_days) is not int
        or type(policy.hold_max_days) is not int
        or type(policy.batch_size) is not int
        or type(policy.max_batch_size) is not int
        or type(policy.max_batches) is not int
        or policy.success_days < 90
        or policy.failure_days < 180
        or policy.hold_max_days <= 0
        or not 1 <= policy.batch_size <= policy.max_batch_size
        or not 1 <= policy.max_batch_size <= 5000
        or not 1 <= policy.max_batches <= 100
    ):
        raise RetentionValidationError("The configured retention policy is invalid.")
    return policy


def _aware_now(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise RetentionValidationError("A timezone-aware datetime is required.")
    return value.astimezone(UTC)


def _contains_ip_literal(value: str) -> bool:
    for token in value.replace(",", " ").split():
        candidate = token.strip("[]()")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def create_hold(
    *,
    event_id: int,
    reason: str,
    created_by: str,
    expires_at: datetime,
    now: datetime | None = None,
) -> int:
    """Create or replace an expired investigative hold for one event.

    Hold creation takes a blocking per-event advisory lock (namespace 7381).
    The retention function takes the matching ``pg_try_advisory_xact_lock`` for
    each candidate event, so a successful hold either commits before retention
    evaluates the row or causes retention to skip that row while the hold
    transaction still holds the lock.  This avoids requiring UPDATE privilege on
    ``security_events`` just to take ``FOR UPDATE`` row locks.
    """
    reference = _aware_now(now)
    policy = retention_policy()
    if type(event_id) is not int or event_id <= 0:
        raise RetentionValidationError("A valid security event id is required.")
    if not isinstance(reason, str):
        raise RetentionValidationError("A hold reason is required.")
    reason = reason.strip()
    if not reason or len(reason) > 255 or "@" in reason or _contains_ip_literal(reason):
        raise RetentionValidationError("The hold reason is invalid.")
    if not isinstance(created_by, str):
        raise RetentionValidationError("A hold creator is required.")
    created_by = created_by.strip()
    if not created_by or len(created_by) > 120 or "@" in created_by:
        raise RetentionValidationError("The hold creator is invalid.")
    if not isinstance(expires_at, datetime):
        raise RetentionValidationError("A valid hold expiry is required.")
    expires_at = _aware_now(expires_at)
    if expires_at <= reference:
        raise RetentionValidationError("Hold expiry must be in the future.")
    if expires_at > reference + timedelta(days=policy.hold_max_days):
        raise RetentionValidationError("Hold expiry exceeds the configured maximum.")

    try:
        # Serialize hold creation against the retention function for this event.
        # The function uses the matching pg_try_advisory_xact_lock namespace/id.
        db.session.execute(
            text("SELECT pg_advisory_xact_lock(:namespace, :event_id)"),
            {"namespace": _EVENT_LOCK_NAMESPACE, "event_id": event_id},
        )
        event = db.session.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
        if event is None:
            raise RetentionValidationError("The security event does not exist.")

        existing = db.session.scalar(
            select(SecurityEventRetentionHold)
            .where(SecurityEventRetentionHold.security_event_id == event_id)
            .with_for_update()
        )
        if existing is not None and existing.expires_at > reference:
            raise RetentionHoldExists("The security event already has an active hold.")
        if existing is not None:
            existing.reason = reason
            existing.created_by = created_by
            existing.created_at = reference
            existing.expires_at = expires_at
            hold_id = existing.id
        else:
            hold = SecurityEventRetentionHold(
                security_event_id=event_id,
                reason=reason,
                created_by=created_by,
                created_at=reference,
                expires_at=expires_at,
            )
            db.session.add(hold)
            db.session.flush()
            hold_id = hold.id
        db.session.commit()
        return hold_id
    except RetentionError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        db.session.rollback()
        raise RetentionHoldExists("The security event already has an active hold.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise RetentionRunError("Unable to create the investigative hold.") from exc


def _insert_run(
    engine: Engine,
    *,
    run_id: str,
    batch_index: int,
    scope: str,
    cutoff: datetime,
    deleted_count: int,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    error_code: str | None = None,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO security_event_retention_runs "
                "(run_id, batch_index, scope, cutoff, deleted_count, status, "
                "error_code, started_at, finished_at) "
                "VALUES (:run_id, :batch_index, :scope, :cutoff, :deleted_count, "
                ":status, :error_code, :started_at, :finished_at)"
            ),
            {
                "run_id": run_id,
                "batch_index": batch_index,
                "scope": scope,
                "cutoff": cutoff,
                "deleted_count": deleted_count,
                "status": status,
                "error_code": error_code,
                "started_at": started_at,
                "finished_at": finished_at,
            },
        )


def run_retention(
    engine: Engine,
    *,
    batch_size: int | None = None,
    max_batches: int | None = None,
    now: datetime | None = None,
) -> RetentionRunSummary:
    """Run bounded retention batches through the approved runner engine."""
    if not current_app.config.get("SECURITY_EVENT_RETENTION_ENABLED", True):
        raise RetentionValidationError("Security-event retention is disabled.")

    reference = _aware_now(now)
    policy = retention_policy()
    batch_size = policy.batch_size if batch_size is None else batch_size
    max_batches = policy.max_batches if max_batches is None else max_batches
    if type(batch_size) is not int or not 1 <= batch_size <= policy.max_batch_size:
        raise RetentionValidationError("The retention batch size is invalid.")
    if type(max_batches) is not int or not 1 <= max_batches <= 100:
        raise RetentionValidationError("The maximum batch count is invalid.")

    cutoffs = {
        RETENTION_SCOPE_SUCCESS: reference - timedelta(days=policy.success_days),
        RETENTION_SCOPE_FAILURE: reference - timedelta(days=policy.failure_days),
    }
    run_id = str(uuid4())
    total_deleted = 0
    total_batches = 0
    last_deleted = 0
    current_scope = RETENTION_SCOPE_SUCCESS

    lock_connection = engine.connect()
    try:
        acquired = lock_connection.execute(
            text("SELECT pg_try_advisory_lock(:key)"),
            {"key": _ADVISORY_LOCK_KEY},
        ).scalar()
        if not acquired:
            raise RetentionLocked("Another security-event retention run is active.")

        for scope in (RETENTION_SCOPE_SUCCESS, RETENTION_SCOPE_FAILURE):
            current_scope = scope
            cutoff = cutoffs[scope]
            while total_batches < max_batches:
                started_at = _aware_now()
                try:
                    with engine.begin() as connection:
                        last_deleted = int(
                            connection.execute(
                                text(
                                    "SELECT public.prune_security_events("
                                    ":scope, :cutoff, :batch_size, "
                                    "CAST(:run_id AS uuid), :batch_index)"
                                ),
                                {
                                    "scope": scope,
                                    "cutoff": cutoff,
                                    "batch_size": batch_size,
                                    "run_id": run_id,
                                    "batch_index": total_batches,
                                },
                            ).scalar_one()
                        )
                except SQLAlchemyError as exc:
                    _insert_run(
                        engine,
                        run_id=run_id,
                        batch_index=total_batches,
                        scope=scope,
                        cutoff=cutoff,
                        deleted_count=0,
                        status=RETENTION_STATUS_FAILED,
                        started_at=started_at,
                        finished_at=_aware_now(),
                        error_code=type(exc).__name__,
                    )
                    raise RetentionRunError("A security-event retention batch failed.") from exc

                total_batches += 1
                total_deleted += last_deleted
                if last_deleted < batch_size:
                    break

            if total_batches >= max_batches:
                break

        if total_batches >= max_batches and last_deleted >= batch_size:
            _insert_run(
                engine,
                run_id=run_id,
                batch_index=total_batches,
                scope=current_scope,
                cutoff=cutoffs[current_scope],
                # Each successful batch already recorded its own deleted_count;
                # the partial marker deletes nothing and must not double-count.
                deleted_count=0,
                status=RETENTION_STATUS_PARTIAL,
                started_at=_aware_now(),
                finished_at=_aware_now(),
            )
            return RetentionRunSummary(run_id, total_deleted, total_batches, "partial")

        return RetentionRunSummary(run_id, total_deleted, total_batches, "success")
    finally:
        try:
            lock_connection.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": _ADVISORY_LOCK_KEY},
            )
        finally:
            lock_connection.close()
