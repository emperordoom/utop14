"""Unit tests for review validation and filter normalization."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.models.product_review import (
    REVIEW_STATUS_HIDDEN,
    REVIEW_STATUS_PUBLISHED,
)
from app.services.reviews import (
    AdminReviewFilters,
    ReviewSummary,
    ReviewValidationError,
    validate_moderation_reason,
    validate_review_comment,
    validate_review_rating,
)


@pytest.mark.parametrize("rating", [1, 2, 3, 4, 5])
def test_rating_accepts_every_valid_star(rating: int) -> None:
    assert validate_review_rating(rating) == rating


@pytest.mark.parametrize("rating", [0, 6, -1, 100])
def test_rating_rejects_out_of_range(rating: int) -> None:
    with pytest.raises(ReviewValidationError):
        validate_review_rating(rating)


@pytest.mark.parametrize(
    "rating",
    ["5", "4.5", 4.5, Decimal("4"), True, False, None, object()],
)
def test_rating_rejects_non_integer_types(rating: object) -> None:
    with pytest.raises(ReviewValidationError):
        validate_review_rating(rating)


def test_comment_is_trimmed_and_unicode_is_preserved() -> None:
    assert validate_review_comment("  Heavyweight — oversized 🔥  ") == "Heavyweight — oversized 🔥"


@pytest.mark.parametrize("comment", ["", "   ", "\n\t", None, 123])
def test_comment_rejects_empty_or_non_text(comment: object) -> None:
    with pytest.raises(ReviewValidationError):
        validate_review_comment(comment)


def test_comment_length_boundary() -> None:
    assert validate_review_comment("a" * 2000) == "a" * 2000
    with pytest.raises(ReviewValidationError):
        validate_review_comment("a" * 2001)


def test_moderation_reason_required_when_hiding() -> None:
    with pytest.raises(ReviewValidationError):
        validate_moderation_reason(None, required=True)
    with pytest.raises(ReviewValidationError):
        validate_moderation_reason("   ", required=True)
    assert validate_moderation_reason("  Spam  ", required=True) == "Spam"


def test_moderation_reason_optional_when_publishing() -> None:
    assert validate_moderation_reason(None, required=False) is None
    assert validate_moderation_reason("", required=False) is None
    assert validate_moderation_reason("  Restored  ", required=False) == "Restored"


def test_moderation_reason_length_limit() -> None:
    with pytest.raises(ReviewValidationError):
        validate_moderation_reason("a" * 501, required=True)


def test_admin_filters_normalize_values() -> None:
    filters = AdminReviewFilters.from_values(
        status="HIDDEN",
        rating="5",
        product="  void  ",
        q="  buyer@example.com  ",
    )
    assert filters.status == REVIEW_STATUS_HIDDEN
    assert filters.rating == 5
    assert filters.product == "void"
    assert filters.query == "buyer@example.com"
    assert filters.as_query_params() == {
        "status": REVIEW_STATUS_HIDDEN,
        "rating": "5",
        "product": "void",
        "q": "buyer@example.com",
    }


def test_admin_filters_drop_invalid_values() -> None:
    filters = AdminReviewFilters.from_values(
        status="deleted",
        rating="9",
        product="",
        q="",
    )
    assert filters.status is None
    assert filters.rating is None
    assert filters.product is None
    assert filters.query is None
    assert filters.as_query_params() == {}


def test_review_summary_percentage_handles_zero_total() -> None:
    summary = ReviewSummary(average=0.0, total=0, distribution={1: 0, 2: 0, 3: 0, 4: 0, 5: 0})
    assert summary.has_reviews is False
    assert summary.percentage(5) == 0


def test_review_summary_percentage_rounds() -> None:
    summary = ReviewSummary(
        average=4.0,
        total=3,
        distribution={1: 0, 2: 0, 3: 1, 4: 0, 5: 2},
    )
    assert summary.has_reviews is True
    assert summary.percentage(5) == 67
    assert summary.percentage(3) == 33
    assert summary.percentage(1) == 0


def test_review_status_constants_are_stable() -> None:
    assert REVIEW_STATUS_PUBLISHED == "published"
    assert REVIEW_STATUS_HIDDEN == "hidden"
