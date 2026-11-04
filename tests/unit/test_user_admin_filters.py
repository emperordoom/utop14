"""Unit tests for admin user directory filter normalization."""

from __future__ import annotations

from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.user_admin import AdminUserFilters


def test_filters_trim_and_normalize_values() -> None:
    filters = AdminUserFilters.from_values(
        q="  buyer@example.com  ",
        role="  ADMIN ",
        status=" INACTIVE ",
    )

    assert filters.query == "buyer@example.com"
    assert filters.role == ROLE_ADMIN
    assert filters.status == "inactive"


def test_filters_reject_unknown_values() -> None:
    filters = AdminUserFilters.from_values(
        q="",
        role="owner",
        status="pending",
    )

    assert filters.query is None
    assert filters.role is None
    assert filters.status is None


def test_filters_cap_search_length() -> None:
    filters = AdminUserFilters.from_values(q="a" * 200)

    assert filters.query is not None
    assert len(filters.query) == 80


def test_filters_accept_every_existing_role() -> None:
    for role in (ROLE_CUSTOMER, ROLE_OPERATOR, ROLE_ADMIN):
        assert AdminUserFilters.from_values(role=role).role == role


def test_query_params_include_only_active_filters() -> None:
    filters = AdminUserFilters.from_values(q="needle", role=ROLE_OPERATOR, status="active")

    assert filters.as_query_params() == {
        "q": "needle",
        "role": ROLE_OPERATOR,
        "status": "active",
    }
    assert AdminUserFilters().as_query_params() == {}
