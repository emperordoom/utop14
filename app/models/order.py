"""Order and immutable order-line models."""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Final

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.product import Product
    from app.models.product_variant import ProductVariant
    from app.models.user import User

ORDER_STATUS_PENDING: Final = "pending"
ORDER_STATUSES: Final[tuple[str, ...]] = (
    "pending",
    "processing",
    "shipped",
    "delivered",
    "cancelled",
)

PAYMENT_STATUS_UNPAID: Final = "unpaid"
PAYMENT_STATUSES: Final[tuple[str, ...]] = (
    "unpaid",
    "paid",
    "refunded",
    "failed",
)


class Order(TimestampMixin, Base):
    """A customer order with server-calculated totals and snapshotted lines."""

    __tablename__ = "orders"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')",
            name="order_status_valid",
        ),
        CheckConstraint(
            "payment_status IN ('unpaid', 'paid', 'refunded', 'failed')",
            name="payment_status_valid",
        ),
        CheckConstraint("subtotal >= 0", name="order_subtotal_non_negative"),
        CheckConstraint("shipping_cost >= 0", name="order_shipping_non_negative"),
        CheckConstraint("total >= 0", name="order_total_non_negative"),
        Index("ix_orders_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    order_number: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ORDER_STATUS_PENDING,
        server_default=text("'pending'"),
    )
    payment_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=PAYMENT_STATUS_UNPAID,
        server_default=text("'unpaid'"),
    )
    recipient_name: Mapped[str] = mapped_column(String(120), nullable=False)
    recipient_phone: Mapped[str] = mapped_column(String(32), nullable=False)
    shipping_address: Mapped[str] = mapped_column(String(255), nullable=False)
    shipping_city: Mapped[str] = mapped_column(String(120), nullable=False)
    shipping_postal_code: Mapped[str] = mapped_column(String(20), nullable=False)
    subtotal: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    shipping_cost: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default=text("0"),
    )
    total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    user: Mapped[User] = relationship()
    items: Mapped[list[OrderItem]] = relationship(
        back_populates="order",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="OrderItem.id",
    )

    @property
    def item_count(self) -> int:
        """Return the total quantity across all order lines."""
        return sum(item.quantity for item in self.items)

    def __repr__(self) -> str:
        return f"<Order {self.order_number!r} status={self.status!r}>"


class OrderItem(Base):
    """A historical order line preserving name, SKU, variant and price."""

    __tablename__ = "order_items"
    __table_args__ = (
        CheckConstraint("unit_price >= 0", name="order_item_unit_price_non_negative"),
        CheckConstraint("quantity > 0", name="order_item_quantity_positive"),
        CheckConstraint("line_total >= 0", name="order_item_line_total_non_negative"),
        Index("ix_order_items_order_id", "order_id"),
        Index("ix_order_items_product_id", "product_id"),
        Index("ix_order_items_variant_id", "variant_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(
        ForeignKey("orders.id", ondelete="CASCADE"),
        nullable=False,
    )
    product_id: Mapped[int | None] = mapped_column(
        ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,
    )
    variant_id: Mapped[int | None] = mapped_column(
        ForeignKey("product_variants.id", ondelete="SET NULL"),
        nullable=True,
    )
    product_name: Mapped[str] = mapped_column(String(120), nullable=False)
    sku: Mapped[str] = mapped_column(String(64), nullable=False)
    size: Mapped[str] = mapped_column(String(20), nullable=False)
    color: Mapped[str] = mapped_column(String(40), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    line_total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    order: Mapped[Order] = relationship(back_populates="items")
    product: Mapped[Product | None] = relationship()
    variant: Mapped[ProductVariant | None] = relationship()

    def __repr__(self) -> str:
        return f"<OrderItem order_id={self.order_id!r} sku={self.sku!r}>"
