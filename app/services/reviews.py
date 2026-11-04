"""Verified-purchase review, aggregate and moderation services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import Order, OrderItem, Product, ProductReview, User
from app.models.order import ORDER_STATUS_DELIVERED
from app.models.payment import PAYMENT_STATUS_PAID
from app.models.product_review import (
    REVIEW_MAX_COMMENT_LENGTH,
    REVIEW_MAX_MODERATION_REASON,
    REVIEW_MAX_RATING,
    REVIEW_MIN_RATING,
    REVIEW_STATUS_HIDDEN,
    REVIEW_STATUS_PUBLISHED,
    REVIEW_STATUSES,
)

_MAX_FILTER_LENGTH: Final = 80


class ReviewError(Exception):
    """Base error for review operations."""


class ReviewNotFound(ReviewError):
    """Raised when a review is absent or not owned by the requesting user."""


class ReviewValidationError(ReviewError):
    """Raised when rating, comment or moderation input is invalid."""


class ReviewEligibilityError(ReviewError):
    """Raised when no verified purchase permits the requested review."""


class ReviewConflictError(ReviewError):
    """Raised when an order item already has a review."""


@dataclass(frozen=True, slots=True)
class ReviewSummary:
    """Public aggregate calculated only from published reviews."""

    average: float
    total: int
    distribution: dict[int, int]

    @property
    def has_reviews(self) -> bool:
        """Whether any published review exists."""
        return self.total > 0

    def percentage(self, rating: int) -> int:
        """Return the whole-percent share for one star value."""
        if self.total <= 0:
            return 0
        return round(self.distribution.get(rating, 0) * 100 / self.total)


@dataclass(frozen=True, slots=True)
class ReviewEligibility:
    """Server-derived review eligibility for one customer and product."""

    eligible: bool
    message: str
    order_item_id: int | None = None
    order_number: str | None = None


@dataclass(frozen=True, slots=True)
class AdminReviewFilters:
    """Normalized admin review-list filters."""

    status: str | None = None
    rating: int | None = None
    product: str | None = None
    query: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        status: str | None = None,
        rating: object = None,
        product: str | None = None,
        q: str | None = None,
    ) -> AdminReviewFilters:
        """Build filters from untrusted query-string values."""
        normalized_status = status.strip().lower() if isinstance(status, str) else None
        if normalized_status not in REVIEW_STATUSES:
            normalized_status = None

        normalized_rating: int | None = None
        if type(rating) is int and REVIEW_MIN_RATING <= rating <= REVIEW_MAX_RATING:
            normalized_rating = rating
        elif isinstance(rating, str) and rating.strip().isdigit():
            candidate = int(rating.strip())
            if REVIEW_MIN_RATING <= candidate <= REVIEW_MAX_RATING:
                normalized_rating = candidate

        normalized_product = (
            product.strip()[:_MAX_FILTER_LENGTH] if isinstance(product, str) else None
        )
        normalized_query = q.strip()[:_MAX_FILTER_LENGTH] if isinstance(q, str) else None
        return cls(
            status=normalized_status,
            rating=normalized_rating,
            product=normalized_product or None,
            query=normalized_query or None,
        )

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {
            "status": self.status,
            "rating": str(self.rating) if self.rating is not None else None,
            "product": self.product,
            "q": self.query,
        }
        return {key: value for key, value in values.items() if value}


@dataclass(frozen=True, slots=True)
class ReviewModerationResult:
    """Outcome of one admin moderation action."""

    review: ProductReview
    message: str
    category: str = "success"


def validate_review_rating(value: object) -> int:
    """Return a strict integer rating from 1 to 5.

    Only a genuine ``int`` is accepted.  Booleans (an ``int`` subclass),
    strings, floats and ``Decimal`` values are rejected rather than coerced.
    """
    if type(value) is not int:
        raise ReviewValidationError("Rating must be a whole number from 1 to 5.")
    if not REVIEW_MIN_RATING <= value <= REVIEW_MAX_RATING:
        raise ReviewValidationError("Rating must be between 1 and 5 stars.")
    return value


def validate_review_comment(value: object) -> str:
    """Trim and validate a review comment while preserving Unicode content."""
    if not isinstance(value, str):
        raise ReviewValidationError("A review comment is required.")
    cleaned = value.strip()
    if not cleaned:
        raise ReviewValidationError("A review comment is required.")
    if len(cleaned) > REVIEW_MAX_COMMENT_LENGTH:
        raise ReviewValidationError(
            f"Review comments must be {REVIEW_MAX_COMMENT_LENGTH} characters or fewer."
        )
    return cleaned


def validate_moderation_reason(value: object, *, required: bool) -> str | None:
    """Trim and bound an optional or required moderation reason."""
    if value is None:
        if required:
            raise ReviewValidationError("A moderation reason is required when hiding a review.")
        return None
    if not isinstance(value, str):
        raise ReviewValidationError("A moderation reason must be text.")
    cleaned = value.strip()
    if not cleaned:
        if required:
            raise ReviewValidationError("A moderation reason is required when hiding a review.")
        return None
    if len(cleaned) > REVIEW_MAX_MODERATION_REASON:
        raise ReviewValidationError(
            f"A moderation reason must be {REVIEW_MAX_MODERATION_REASON} characters or fewer."
        )
    return cleaned


def _eligible_order_item_statement(user_id: int, product_id: int):
    """Select delivered, paid, unreviewed order lines for one customer/product."""
    return (
        select(OrderItem)
        .join(OrderItem.order)
        .options(joinedload(OrderItem.order))
        .where(
            Order.user_id == user_id,
            Order.status == ORDER_STATUS_DELIVERED,
            Order.payment_status == PAYMENT_STATUS_PAID,
            OrderItem.product_id == product_id,
            ~OrderItem.review.has(),
        )
        .order_by(Order.created_at.asc(), OrderItem.id.asc())
    )


def _has_purchased_product(user_id: int, product_id: int) -> bool:
    statement = (
        select(OrderItem.id)
        .join(OrderItem.order)
        .where(
            Order.user_id == user_id,
            OrderItem.product_id == product_id,
        )
        .limit(1)
    )
    return db.session.scalar(statement) is not None


def _has_reviewed_purchase(user_id: int, product_id: int) -> bool:
    statement = (
        select(ProductReview.id)
        .where(
            ProductReview.user_id == user_id,
            ProductReview.product_id == product_id,
        )
        .limit(1)
    )
    return db.session.scalar(statement) is not None


def _ineligibility_message(user_id: int, product_id: int) -> str:
    if _has_reviewed_purchase(user_id, product_id):
        return "You have already reviewed every eligible purchase of this product."
    if not _has_purchased_product(user_id, product_id):
        return "Reviews are open to verified buyers only. Purchase this piece first."
    return "Reviews open after an order is delivered and paid."


def get_review_eligibility(user_id: int, product_id: int) -> ReviewEligibility:
    """Return whether the customer may review this product and why."""
    statement = _eligible_order_item_statement(user_id, product_id).limit(1)
    item = db.session.scalar(statement)
    if item is not None:
        order_number = item.order.order_number
        return ReviewEligibility(
            eligible=True,
            message=f"Verified purchase · {order_number}",
            order_item_id=item.id,
            order_number=order_number,
        )
    return ReviewEligibility(
        eligible=False,
        message=_ineligibility_message(user_id, product_id),
    )


def _select_order_item(items: list[OrderItem], order_item_id: int | None) -> OrderItem:
    """Resolve a client-supplied order item against the server's eligible set."""
    if order_item_id is None:
        return items[0]
    if type(order_item_id) is not int:
        raise ReviewValidationError("The selected purchase is invalid.")
    for item in items:
        if item.id == order_item_id:
            return item
    raise ReviewEligibilityError("That purchase is not eligible for this product.")


def create_product_review(
    user_id: int,
    product_id: int,
    *,
    rating: object,
    comment: object,
    order_item_id: int | None = None,
) -> ProductReview:
    """Create one review for an eligible, not-yet-reviewed order line."""
    clean_rating = validate_review_rating(rating)
    clean_comment = validate_review_comment(comment)

    try:
        statement = _eligible_order_item_statement(user_id, product_id).with_for_update(
            of=OrderItem
        )
        eligible_items = list(db.session.scalars(statement).all())
        if not eligible_items:
            if _has_reviewed_purchase(user_id, product_id):
                raise ReviewConflictError("You have already reviewed this purchase.")
            raise ReviewEligibilityError(_ineligibility_message(user_id, product_id))

        order_item = _select_order_item(eligible_items, order_item_id)
        existing = db.session.scalar(
            select(ProductReview.id)
            .where(ProductReview.order_item_id == order_item.id)
            .with_for_update()
        )
        if existing is not None:
            raise ReviewConflictError("You have already reviewed this purchase.")

        review = ProductReview(
            product_id=product_id,
            user_id=user_id,
            order_item_id=order_item.id,
            rating=clean_rating,
            comment=clean_comment,
            status=REVIEW_STATUS_PUBLISHED,
        )
        db.session.add(review)
        db.session.commit()
        return review
    except ReviewError:
        db.session.rollback()
        raise
    except IntegrityError as exc:
        # The unique constraint on order_item_id is the final arbiter for
        # concurrent submissions of the same purchase.
        db.session.rollback()
        raise ReviewConflictError("You have already reviewed this purchase.") from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise ReviewError("Your review could not be saved. Please try again.") from exc


def update_product_review(
    user_id: int,
    review_id: int,
    *,
    rating: object,
    comment: object,
) -> ProductReview:
    """Edit only the owner's rating and comment, preserving moderation state."""
    clean_rating = validate_review_rating(rating)
    clean_comment = validate_review_comment(comment)

    try:
        review = db.session.scalar(
            select(ProductReview)
            .where(
                ProductReview.id == review_id,
                ProductReview.user_id == user_id,
            )
            .with_for_update()
        )
        if review is None:
            raise ReviewNotFound("Review not found.")

        review.rating = clean_rating
        review.comment = clean_comment
        db.session.commit()
        return review
    except ReviewError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise ReviewError("Your review could not be updated. Please try again.") from exc


def get_product_reviews(
    product_id: int,
    *,
    page: int = 1,
    per_page: int = 5,
):
    """Return a paginated list of published reviews newest first."""
    statement = (
        select(ProductReview)
        .options(joinedload(ProductReview.user))
        .where(
            ProductReview.product_id == product_id,
            ProductReview.status == REVIEW_STATUS_PUBLISHED,
        )
        .order_by(ProductReview.created_at.desc(), ProductReview.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_review_summary(product_id: int) -> ReviewSummary:
    """Calculate average, count and distribution from published reviews only."""
    rows = db.session.execute(
        select(ProductReview.rating, func.count(ProductReview.id))
        .where(
            ProductReview.product_id == product_id,
            ProductReview.status == REVIEW_STATUS_PUBLISHED,
        )
        .group_by(ProductReview.rating)
    ).all()

    distribution = dict.fromkeys(range(REVIEW_MIN_RATING, REVIEW_MAX_RATING + 1), 0)
    total = 0
    weighted = 0
    for rating, count in rows:
        if rating in distribution:
            distribution[rating] = count
        total += count
        weighted += rating * count

    average = round(weighted / total, 2) if total else 0.0
    return ReviewSummary(
        average=average,
        total=total,
        distribution=distribution,
    )


def get_user_review(user_id: int, review_id: int) -> ProductReview | None:
    """Return one review only when it belongs to the requesting customer."""
    statement = (
        select(ProductReview)
        .options(
            joinedload(ProductReview.product),
            joinedload(ProductReview.order_item).joinedload(OrderItem.order),
        )
        .where(
            ProductReview.id == review_id,
            ProductReview.user_id == user_id,
        )
    )
    return db.session.scalar(statement)


def get_user_reviews(
    user_id: int,
    *,
    page: int = 1,
    per_page: int = 10,
):
    """Return the customer's own review history, including hidden reviews."""
    statement = (
        select(ProductReview)
        .options(joinedload(ProductReview.product))
        .where(ProductReview.user_id == user_id)
        .order_by(ProductReview.created_at.desc(), ProductReview.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def list_admin_reviews(
    filters: AdminReviewFilters,
    *,
    page: int = 1,
    per_page: int = 20,
):
    """Return a paginated, filtered moderation queue."""
    conditions = []
    if filters.status is not None:
        conditions.append(ProductReview.status == filters.status)
    if filters.rating is not None:
        conditions.append(ProductReview.rating == filters.rating)
    if filters.product is not None:
        pattern = f"%{_escape_like(filters.product)}%"
        conditions.append(
            or_(
                Product.name.ilike(pattern, escape="\\"),
                Product.slug.ilike(pattern, escape="\\"),
            )
        )
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                User.full_name.ilike(pattern, escape="\\"),
                User.email.ilike(pattern, escape="\\"),
            )
        )

    statement = (
        select(ProductReview)
        .join(ProductReview.product)
        .join(ProductReview.user)
        .options(
            joinedload(ProductReview.product),
            joinedload(ProductReview.user),
            joinedload(ProductReview.moderated_by),
            joinedload(ProductReview.order_item),
        )
        .where(*conditions)
        .order_by(ProductReview.created_at.desc(), ProductReview.id.desc())
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_admin_review(review_id: int) -> ProductReview | None:
    """Return one review with product, reviewer and moderation context loaded."""
    statement = (
        select(ProductReview)
        .options(
            joinedload(ProductReview.product),
            joinedload(ProductReview.user),
            joinedload(ProductReview.moderated_by),
            joinedload(ProductReview.order_item).joinedload(OrderItem.order),
        )
        .where(ProductReview.id == review_id)
    )
    return db.session.scalar(statement)


def set_review_visibility(
    review_id: int,
    admin_user_id: int,
    status: str,
    *,
    reason: object = None,
    now: datetime | None = None,
) -> ReviewModerationResult:
    """Hide or publish one review while preserving its rating and comment."""
    if status not in REVIEW_STATUSES:
        raise ReviewValidationError("Choose a valid review status.")

    clean_reason = validate_moderation_reason(
        reason,
        required=status == REVIEW_STATUS_HIDDEN,
    )
    now = now or datetime.now(UTC)

    try:
        review = db.session.scalar(
            select(ProductReview).where(ProductReview.id == review_id).with_for_update()
        )
        if review is None:
            raise ReviewNotFound("Review not found.")

        if review.status == status:
            db.session.commit()
            return ReviewModerationResult(
                review,
                f"This review is already {status}.",
                "info",
            )

        review.status = status
        review.moderated_by_user_id = admin_user_id
        review.moderated_at = now
        # Publishing without a new reason preserves the last audit reason.
        if clean_reason is not None:
            review.moderation_reason = clean_reason
        db.session.commit()
        message = (
            "Review hidden. It no longer contributes to public aggregates."
            if status == REVIEW_STATUS_HIDDEN
            else "Review published. It now contributes to public aggregates."
        )
        return ReviewModerationResult(review, message, "success")
    except ReviewError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise ReviewError("The review could not be updated. Please try again.") from exc
