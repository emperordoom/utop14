"""Unit tests for security-event list filters and page normalization."""

from __future__ import annotations

from datetime import date

import pytest
from flask import render_template_string

from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
)
from app.services.security_event_admin import (
    MAX_PAGE,
    AdminSecurityEventFilters,
    normalize_page,
)

VALID_REQUEST_ID = "12345678-1234-5678-1234-567812345678"
NORMALIZED_REQUEST_ID = "12345678123456781234567812345678"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, 1),
        (20, 20),
        (MAX_PAGE, MAX_PAGE),
        (MAX_PAGE + 1, MAX_PAGE),
        (0, 1),
        (-10, 1),
        (None, 1),
        ("5", 1),
        (True, 1),
        (False, 1),
        (1.5, 1),
    ],
)
def test_normalize_page_bounds_and_defaults(value: object, expected: int) -> None:
    assert normalize_page(value) == expected


def test_max_page_is_one_thousand() -> None:
    assert MAX_PAGE == 1000


def test_empty_filter_values_are_unset() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type="",
        outcome="   ",
        reason="",
        date_from=" ",
        date_to="",
        request_id=" ",
        identifier_hash="",
        actor_user_id="",
        subject_user_id=" ",
    )

    assert filters.is_valid
    assert filters.event_type is None
    assert filters.outcome is None
    assert filters.reason_code is None
    assert filters.date_from is None
    assert filters.date_to is None
    assert filters.request_id is None
    assert filters.identifier_hash is None
    assert filters.actor_user_id is None
    assert filters.subject_user_id is None
    assert filters.as_query_params() == {}


def test_valid_filters_normalize_and_serialize() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason=SECURITY_REASON_UNKNOWN_ACCOUNT,
        date_from="2026-11-01",
        date_to="2026-11-02",
        request_id=VALID_REQUEST_ID,
        identifier_hash="a" * 64,
        actor_user_id="42",
        subject_user_id="0007",
    )

    assert filters.is_valid
    assert filters.event_type == SECURITY_EVENT_LOGIN_FAILED
    assert filters.outcome == SECURITY_OUTCOME_FAILURE
    assert filters.reason_code == SECURITY_REASON_UNKNOWN_ACCOUNT
    assert filters.date_from == date(2026, 11, 1)
    assert filters.date_to == date(2026, 11, 2)
    assert filters.request_id == NORMALIZED_REQUEST_ID
    assert filters.identifier_hash == "a" * 64
    assert filters.actor_user_id == 42
    assert filters.subject_user_id == 7
    assert filters.as_query_params() == {
        "event_type": SECURITY_EVENT_LOGIN_FAILED,
        "outcome": SECURITY_OUTCOME_FAILURE,
        "reason": SECURITY_REASON_UNKNOWN_ACCOUNT,
        "date_from": "2026-11-01",
        "date_to": "2026-11-02",
        "request_id": NORMALIZED_REQUEST_ID,
        "identifier_hash": "a" * 64,
        "actor_user_id": "42",
        "subject_user_id": "7",
    }


def test_reason_without_event_type_derives_event_type() -> None:
    filters = AdminSecurityEventFilters.from_values(
        reason=SECURITY_REASON_USER_REQUESTED,
    )

    assert filters.is_valid
    assert filters.event_type == SECURITY_EVENT_LOGOUT
    assert filters.reason_code == SECURITY_REASON_USER_REQUESTED


def test_reason_event_type_conflict_fails_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
        reason=SECURITY_REASON_USER_REQUESTED,
    )

    assert not filters.is_valid
    assert any("not compatible" in error for error in filters.errors)
    assert filters.event_type == SECURITY_EVENT_LOGIN_SUCCEEDED
    assert filters.reason_code == SECURITY_REASON_USER_REQUESTED


def test_invalid_allowlisted_values_fail_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type="auth.deleted",
        outcome="denied",
        reason="magic",
    )

    assert not filters.is_valid
    assert filters.event_type is None
    assert filters.outcome is None
    assert filters.reason_code is None
    assert any("event type" in error.lower() for error in filters.errors)
    assert any("outcome" in error.lower() for error in filters.errors)
    assert any("reason" in error.lower() for error in filters.errors)


def test_invalid_dates_fail_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        date_from="not-a-date",
        date_to="2026-13-40",
    )

    assert not filters.is_valid
    assert filters.date_from is None
    assert filters.date_to is None
    assert any("From date" in error for error in filters.errors)
    assert any("To date" in error for error in filters.errors)


def test_reversed_date_range_fails_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        date_from="2026-11-03",
        date_to="2026-11-01",
    )

    assert not filters.is_valid
    assert filters.date_from == date(2026, 11, 3)
    assert filters.date_to == date(2026, 11, 1)
    assert any("on or before" in error for error in filters.errors)


def test_maximum_date_is_accepted() -> None:
    filters = AdminSecurityEventFilters.from_values(
        date_from="9999-12-31",
        date_to="9999-12-31",
    )

    assert filters.is_valid
    assert filters.date_from == date.max
    assert filters.date_to == date.max


def test_request_id_validation_and_normalization() -> None:
    valid = AdminSecurityEventFilters.from_values(request_id=VALID_REQUEST_ID)
    invalid = AdminSecurityEventFilters.from_values(request_id="not-a-request-id")

    assert valid.is_valid
    assert valid.request_id == NORMALIZED_REQUEST_ID
    assert not invalid.is_valid
    assert invalid.request_id is None
    assert any("Request ID" in error for error in invalid.errors)


def test_identifier_hash_requires_lowercase_64_hex() -> None:
    valid = AdminSecurityEventFilters.from_values(identifier_hash="a" * 64)
    uppercase = AdminSecurityEventFilters.from_values(identifier_hash="A" * 64)
    too_short = AdminSecurityEventFilters.from_values(identifier_hash="a" * 63)
    too_long = AdminSecurityEventFilters.from_values(identifier_hash="a" * 65)

    assert valid.is_valid
    assert valid.identifier_hash == "a" * 64
    assert not uppercase.is_valid
    assert not too_short.is_valid
    assert not too_long.is_valid
    assert uppercase.identifier_hash is None


def test_actor_and_subject_ids_are_range_checked() -> None:
    valid = AdminSecurityEventFilters.from_values(
        actor_user_id="2147483647",
        subject_user_id="1",
    )
    assert valid.is_valid
    assert valid.actor_user_id == 2_147_483_647
    assert valid.subject_user_id == 1

    for value in ("0", "-1", "abc", "2147483648", "9" * 11, "١٢"):
        filters = AdminSecurityEventFilters.from_values(
            actor_user_id=value,
            subject_user_id=value,
        )
        assert not filters.is_valid
        assert filters.actor_user_id is None
        assert filters.subject_user_id is None


def test_repeated_non_empty_filter_values_fail_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type=[SECURITY_EVENT_LOGOUT, SECURITY_EVENT_LOGIN_FAILED],
    )

    assert not filters.is_valid
    assert filters.event_type is None
    assert any("only once" in error for error in filters.errors)


def test_one_empty_repeated_value_is_not_ambiguous() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type=["", SECURITY_EVENT_LOGOUT],
    )

    assert filters.is_valid
    assert filters.event_type == SECURITY_EVENT_LOGOUT


def test_overlong_filter_values_fail_closed() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type="a" * 81,
        request_id="a" * 65,
        identifier_hash="a" * 65,
        actor_user_id="9" * 11,
    )

    assert not filters.is_valid
    assert filters.event_type is None
    assert filters.request_id is None
    assert filters.identifier_hash is None
    assert filters.actor_user_id is None
    assert any("too long" in error for error in filters.errors)


def test_direct_invalid_filter_object_fails_closed() -> None:
    filters = AdminSecurityEventFilters(
        event_type="auth.not_real",
        outcome="denied",
        reason_code=SECURITY_REASON_AUTHENTICATED,
        request_id="not-a-request-id",
        identifier_hash="A" * 64,
        actor_user_id=0,
        subject_user_id=-1,
        date_from=date(2026, 11, 3),
        date_to=date(2026, 11, 1),
    )

    assert not filters.is_valid
    assert len(filters.errors) >= 6


def test_direct_reason_conflict_fails_closed() -> None:
    filters = AdminSecurityEventFilters(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        reason_code=SECURITY_REASON_USER_REQUESTED,
    )

    assert not filters.is_valid
    assert any("not compatible" in error for error in filters.errors)


def test_reason_compatible_with_explicit_event_type_is_valid() -> None:
    filters = AdminSecurityEventFilters.from_values(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        reason=SECURITY_REASON_UNKNOWN_ACCOUNT,
    )

    assert filters.is_valid
    assert filters.event_type == SECURITY_EVENT_LOGIN_FAILED
    assert filters.reason_code == SECURITY_REASON_UNKNOWN_ACCOUNT


def test_authenticated_reason_derives_login_succeeded_event_type() -> None:
    filters = AdminSecurityEventFilters.from_values(reason=SECURITY_REASON_AUTHENTICATED)

    assert filters.is_valid
    assert filters.event_type == SECURITY_EVENT_LOGIN_SUCCEEDED


def test_badge_fallbacks_escape_unexpected_values(app) -> None:
    template = """
    {% from "components/security_event_badges.html" import
      security_event_type_badge,
      security_outcome_badge,
      security_reason_badge
    %}
    {{ security_event_type_badge('bad"><script>alert(1)</script>') }}
    {{ security_outcome_badge('<img src=x onerror=alert(1)>') }}
    {{ security_reason_badge('bad"><svg onload=alert(1)>') }}
    """

    html = render_template_string(template)

    assert "<script>" not in html
    assert "<img" not in html
    assert "<svg" not in html
    assert "&lt;script&gt;" in html
    assert html.count("security-event-badge--unknown") == 3
