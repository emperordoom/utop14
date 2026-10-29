"""SQLAlchemy model registry.

Import every model module here so Flask-Migrate/Alembic discovers the complete
metadata during ``flask db migrate`` and at application startup.  Importing
this package never creates tables.
"""

from __future__ import annotations

from app.models.base import Base
from app.models.category import Category
from app.models.product import Product
from app.models.product_image import ProductImage
from app.models.product_variant import ProductVariant

__all__ = [
    "Base",
    "Category",
    "Product",
    "ProductImage",
    "ProductVariant",
]
