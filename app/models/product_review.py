"""Verified-purchase product review model."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Final

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.order import OrderItem
    from app.models.product import Product
    from app.models.user import User

REVIEW_STATUS_PUBLISHED: Final = "published"
REVIEW_STATUS_HIDDEN: Final = "hidden"
REVIEW_STATUSES: Final[tuple[str, ...]] = (
    REVIEW_STATUS_PUBLISHED,
    REVIEW_STATUS_HIDDEN,
)

REVIEW_MIN_RATING: Final = 1
REVIEW_MAX_RATING: Final = 5
REVIEW_MAX_COMMENT_LENGTH: Final = 2000
REVIEW_MAX_MODERATION_REASON: Final = 500


class ProductReview(TimestampMixin, Base):
    """A moderated review tied to one delivered, paid order line.

    A review can never exist without a purchased ``OrderItem``.  The foreign
    keys use ``RESTRICT`` so deactivating or archiving catalog records cannot
    silently erase review history.
    """

    __tablename__ = "product_reviews"
    __table_args__ = (
        CheckConstraint(
            "rating BETWEEN 1 AND 5",
            name="product_review_rating_range",
        ),
        CheckConstraint(
            f"char_length(comment) BETWEEN 1 AND {REVIEW_MAX_COMMENT_LENGTH}",
            name="product_review_comment_length",
        ),
        CheckConstraint(
            "status IN ('published', 'hidden')",
            name="product_review_status_valid",
        ),
        CheckConstraint(
            "status <> 'hidden' OR moderation_reason IS NOT NULL",
            name="product_review_hidden_reason_present",
        ),
        UniqueConstraint(
            "order_item_id",
            name="product_review_order_item_unique",
        ),
        Index(
            "ix_product_reviews_product_id_status_created_at",
            "product_id",
            "status",
            "created_at",
        ),
        Index(
            "ix_product_reviews_user_id_created_at",
            "user_id",
            "created_at",
        ),
        Index("ix_product_reviews_status", "status"),
        Index("ix_product_reviews_rating", "rating"),
        Index("ix_product_reviews_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    order_item_id: Mapped[int] = mapped_column(
        ForeignKey("order_items.id", ondelete="RESTRICT"),
        nullable=False,
    )
    rating: Mapped[int] = mapped_column(Integer, nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=REVIEW_STATUS_PUBLISHED,
        server_default=text("'published'"),
    )
    moderated_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    moderated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    moderation_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    product: Mapped[Product] = relationship(back_populates="reviews")
    user: Mapped[User] = relationship(foreign_keys=[user_id])
    order_item: Mapped[OrderItem] = relationship(back_populates="review")
    moderated_by: Mapped[User | None] = relationship(
        foreign_keys=[moderated_by_user_id],
    )

    @property
    def is_published(self) -> bool:
        """Whether this review contributes to public aggregates."""
        return self.status == REVIEW_STATUS_PUBLISHED

    def __repr__(self) -> str:
        return (
            f"<ProductReview id={self.id!r} product_id={self.product_id!r} "
            f"rating={self.rating!r} status={self.status!r}>"
        )
