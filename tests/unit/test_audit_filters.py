"""Unit tests for admin audit filter normalization."""

from __future__ import annotations

from datetime import date

from app.models.audit_log import AUDIT_ACTION_ROLE_CHANGED
from app.services.audit import AdminAuditFilters


def test_filters_normalize_and_trim_values() -> None:
    filters = AdminAuditFilters.from_values(
        action="user.role_changed",
        actor="  Admin  ",
        target=" target@example.com ",
        date_from="2026-11-01",
        date_to="2026-11-04",
        q=" need ",
    )

    assert filters.action == AUDIT_ACTION_ROLE_CHANGED
    assert filters.actor == "Admin"
    assert filters.target == "target@example.com"
    assert filters.date_from == date(2026, 11, 1)
    assert filters.date_to == date(2026, 11, 4)
    assert filters.query == "need"


def test_filters_accept_maximum_date() -> None:
    filters = AdminAuditFilters.from_values(date_to="9999-12-31")

    assert filters.date_to == date.max


def test_filters_reject_unknown_action_and_invalid_dates() -> None:
    filters = AdminAuditFilters.from_values(
        action="user.deleted",
        date_from="not-a-date",
        date_to="2026-13-40",
    )

    assert filters.action is None
    assert filters.date_from is None
    assert filters.date_to is None


def test_filters_cap_search_length() -> None:
    filters = AdminAuditFilters.from_values(actor="a" * 200, q="b" * 200)

    assert filters.actor is not None and len(filters.actor) == 80
    assert filters.query is not None and len(filters.query) == 80


def test_query_params_include_only_active_filters() -> None:
    filters = AdminAuditFilters.from_values(
        action=AUDIT_ACTION_ROLE_CHANGED,
        actor="admin",
        target="target",
        date_from="2026-11-01",
        date_to="2026-11-04",
        q="search",
    )

    assert filters.as_query_params() == {
        "action": AUDIT_ACTION_ROLE_CHANGED,
        "actor": "admin",
        "target": "target",
        "date_from": "2026-11-01",
        "date_to": "2026-11-04",
        "q": "search",
    }
    assert AdminAuditFilters().as_query_params() == {}


def test_empty_filters_become_none() -> None:
    filters = AdminAuditFilters.from_values(
        action="",
        actor="   ",
        target="",
        date_from="",
        date_to="",
        q="",
    )

    assert filters.as_query_params() == {}
