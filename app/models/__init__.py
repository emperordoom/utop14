"""SQLAlchemy model registry.

Import every model module here so Flask-Migrate/Alembic discovers the complete
metadata during ``flask db migrate`` and at application startup.  Importing
this package never creates tables.
"""

from __future__ import annotations

from app.models.base import Base
from app.models.cart import Cart, CartItem
from app.models.category import Category
from app.models.order import Order, OrderItem
from app.models.payment import Payment
from app.models.payment_proof import PaymentProof
from app.models.product import Product
from app.models.product_image import ProductImage
from app.models.product_variant import ProductVariant
from app.models.user import User

__all__ = [
    "Base",
    "Cart",
    "CartItem",
    "Category",
    "Order",
    "OrderItem",
    "Payment",
    "PaymentProof",
    "Product",
    "ProductImage",
    "ProductVariant",
    "User",
]
