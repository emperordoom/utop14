"""Read-only administrative security-event list service."""

from __future__ import annotations

from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import load_only

from app.extensions import db
from app.models.security_event import SecurityEvent

PER_PAGE: Final = 20
MAX_PAGE: Final = 1000

_LIST_COLUMNS = (
    SecurityEvent.id,
    SecurityEvent.created_at,
    SecurityEvent.event_type,
    SecurityEvent.outcome,
    SecurityEvent.reason_code,
    SecurityEvent.actor_user_id,
    SecurityEvent.actor_email,
    SecurityEvent.subject_user_id,
    SecurityEvent.subject_email,
    SecurityEvent.ip_address,
    SecurityEvent.request_id,
)


def normalize_page(value: object) -> int:
    """Return a safe positive page number bounded by ``MAX_PAGE``."""
    if isinstance(value, bool):
        return 1
    if isinstance(value, int) and value >= 1:
        return min(value, MAX_PAGE)
    return 1


def list_security_events(*, page: int = 1):
    """Return one newest-first page of security events.

    The list deliberately omits identifier hashes, metadata and User-Agent
    values; those remain detail-view concerns.  The page size is fixed at 20.
    """
    statement = (
        select(SecurityEvent)
        .options(load_only(*_LIST_COLUMNS))
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
    )
    return db.paginate(
        statement,
        page=normalize_page(page),
        per_page=PER_PAGE,
        error_out=False,
    )
