"""Read-only dashboard statistics for staff pages."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select

from app.extensions import db
from app.models import Category, Product, ProductVariant, User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR


@dataclass(frozen=True, slots=True)
class AdminStats:
    """Aggregate counts shown on staff dashboards."""

    categories: int
    products: int
    variants: int
    users: int
    customers: int
    operators: int
    admins: int


def _count(model: type, *conditions: object) -> int:
    statement = select(func.count()).select_from(model)
    if conditions:
        statement = statement.where(*conditions)
    return db.session.scalar(statement) or 0


def get_admin_stats() -> AdminStats:
    """Return aggregate catalog and account counts without matching rows."""
    return AdminStats(
        categories=_count(Category),
        products=_count(Product),
        variants=_count(ProductVariant),
        users=_count(User),
        customers=_count(User, User.role == ROLE_CUSTOMER),
        operators=_count(User, User.role == ROLE_OPERATOR),
        admins=_count(User, User.role == ROLE_ADMIN),
    )
