"""Unit tests for security-event list page normalization."""

from __future__ import annotations

import pytest

from app.services.security_event_admin import MAX_PAGE, normalize_page


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
