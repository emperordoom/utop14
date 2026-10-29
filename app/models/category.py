"""Product category model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, Integer, String, Text, text, true
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models.base import Base, TimestampMixin, validate_image_path

if TYPE_CHECKING:
    from app.models.product import Product


class Category(TimestampMixin, Base):
    """A top-level shopping category such as T-shirts or Accessories."""

    __tablename__ = "categories"
    __table_args__ = (CheckConstraint("position >= 0", name="position_non_negative"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    icon: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    position: Mapped[int] = mapped_column(
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

    products: Mapped[list[Product]] = relationship(
        back_populates="category",
        passive_deletes=True,
        order_by="Product.name",
    )

    @validates("icon")
    def _validate_icon(self, _key: str, value: str) -> str:
        return validate_image_path(value)

    def __repr__(self) -> str:
        return f"<Category {self.slug!r}>"
