"""Persistent shopping cart models."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.product_variant import ProductVariant
    from app.models.user import User

_CENT = Decimal("0.01")


class Cart(TimestampMixin, Base):
    """One persistent cart per authenticated account."""

    __tablename__ = "carts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    user: Mapped[User] = relationship()
    items: Mapped[list[CartItem]] = relationship(
        back_populates="cart",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CartItem.id",
    )

    @property
    def line_count(self) -> int:
        """Return the number of distinct variants in the cart."""
        return len(self.items)

    @property
    def item_count(self) -> int:
        """Return the total quantity across all cart lines."""
        return sum(item.quantity for item in self.items)

    @property
    def subtotal(self) -> Decimal:
        """Return the current database-price subtotal, rounded to cents."""
        return sum((item.line_total for item in self.items), Decimal("0.00")).quantize(_CENT)

    def __repr__(self) -> str:
        return f"<Cart user_id={self.user_id!r}>"


class CartItem(TimestampMixin, Base):
    """A quantity of one product variant inside a cart."""

    __tablename__ = "cart_items"
    __table_args__ = (
        CheckConstraint("quantity > 0", name="quantity_positive"),
        UniqueConstraint("cart_id", "variant_id", name="cart_variant"),
        Index("ix_cart_items_variant_id", "variant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    cart_id: Mapped[int] = mapped_column(
        ForeignKey("carts.id", ondelete="CASCADE"),
        nullable=False,
    )
    variant_id: Mapped[int] = mapped_column(
        ForeignKey("product_variants.id", ondelete="CASCADE"),
        nullable=False,
    )
    quantity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )

    cart: Mapped[Cart] = relationship(back_populates="items")
    variant: Mapped[ProductVariant] = relationship()

    @property
    def unit_price(self) -> Decimal:
        """Return the current database price for this item's product."""
        if self.variant is None or self.variant.product is None:
            return Decimal("0.00")
        return self.variant.product.price.quantize(_CENT)

    @property
    def line_total(self) -> Decimal:
        """Return the current price multiplied by the requested quantity."""
        return (self.unit_price * self.quantity).quantize(_CENT)

    @property
    def available_stock(self) -> int:
        """Return the current stock for this item's variant."""
        return self.variant.stock if self.variant is not None else 0

    @property
    def is_available(self) -> bool:
        """Whether the product, category and variant are still purchasable."""
        if self.variant is None or self.variant.product is None:
            return False
        product = self.variant.product
        if product.category is None:
            return False
        return bool(self.variant.is_active and product.is_active and product.category.is_active)

    @property
    def has_enough_stock(self) -> bool:
        """Whether the requested quantity can currently be fulfilled."""
        return self.quantity <= self.available_stock

    @property
    def is_purchasable(self) -> bool:
        """Whether the line is active and fully covered by current stock."""
        return self.is_available and self.has_enough_stock

    def __repr__(self) -> str:
        return f"<CartItem cart_id={self.cart_id!r} variant_id={self.variant_id!r}>"
