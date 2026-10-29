"""Catalog product model."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models.base import Base, TimestampMixin, validate_image_path

if TYPE_CHECKING:
    from app.models.category import Category
    from app.models.product_image import ProductImage
    from app.models.product_variant import ProductVariant


class Product(TimestampMixin, Base):
    """A catalog product with a category, variants and gallery images."""

    __tablename__ = "products"
    __table_args__ = (
        CheckConstraint("price >= 0", name="price_non_negative"),
        Index("ix_products_category_id_is_active", "category_id", "is_active"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    category_id: Mapped[int] = mapped_column(
        ForeignKey("categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    image_path: Mapped[str] = mapped_column(String(255), nullable=False)
    image_alt: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    badge: Mapped[str | None] = mapped_column(String(40), nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    category: Mapped[Category] = relationship(back_populates="products")
    variants: Mapped[list[ProductVariant]] = relationship(
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ProductVariant.id",
    )
    images: Mapped[list[ProductImage]] = relationship(
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ProductImage.position",
    )

    @validates("image_path")
    def _validate_image_path(self, _key: str, value: str) -> str:
        return validate_image_path(value)

    @property
    def available_variants(self) -> list[ProductVariant]:
        """Return active variants in their configured order."""
        return [variant for variant in self.variants if variant.is_active]

    @property
    def is_in_stock(self) -> bool:
        """Whether at least one active variant has stock available."""
        return any(variant.stock > 0 for variant in self.available_variants)

    @property
    def colour_label(self) -> str:
        """Human-readable list of active colourways for product cards."""
        colours = list(dict.fromkeys(variant.color for variant in self.available_variants))
        return " / ".join(colours) if colours else "Unavailable"

    @property
    def primary_image(self) -> ProductImage | None:
        """Return the first gallery image, if any."""
        return self.images[0] if self.images else None

    def __repr__(self) -> str:
        return f"<Product {self.slug!r}>"
