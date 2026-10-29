"""Product variant (size and colour) inventory model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    text,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.product import Product


class ProductVariant(TimestampMixin, Base):
    """A purchasable size/colour combination with its own stock count."""

    __tablename__ = "product_variants"
    __table_args__ = (
        CheckConstraint("stock >= 0", name="stock_non_negative"),
        UniqueConstraint(
            "product_id",
            "size",
            "color",
            name="product_size_color",
        ),
        Index("ix_product_variants_product_id_is_active", "product_id", "is_active"),
        Index("ix_product_variants_size", "size"),
        Index("ix_product_variants_color", "color"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
    )
    size: Mapped[str] = mapped_column(String(20), nullable=False)
    color: Mapped[str] = mapped_column(String(40), nullable=False)
    sku: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    stock: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=true(),
    )

    product: Mapped[Product] = relationship(back_populates="variants")

    def __repr__(self) -> str:
        return f"<ProductVariant {self.sku!r}>"
