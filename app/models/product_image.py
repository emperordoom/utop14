"""Product gallery image model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models.base import Base, TimestampMixin, validate_image_path

if TYPE_CHECKING:
    from app.models.product import Product


class ProductImage(TimestampMixin, Base):
    """An ordered gallery image belonging to a product."""

    __tablename__ = "product_images"
    __table_args__ = (
        CheckConstraint("position >= 0", name="position_non_negative"),
        Index("ix_product_images_product_id_position", "product_id", "position"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
    )
    image_path: Mapped[str] = mapped_column(String(255), nullable=False)
    alt_text: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    position: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )

    product: Mapped[Product] = relationship(back_populates="images")

    @validates("image_path")
    def _validate_image_path(self, _key: str, value: str) -> str:
        return validate_image_path(value)

    def __repr__(self) -> str:
        return f"<ProductImage {self.image_path!r} position={self.position}>"
