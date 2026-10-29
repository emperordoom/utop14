"""Read-only catalog queries shared by storefront routes.

The service layer keeps SQLAlchemy statements out of views and templates.  All
public queries hide inactive categories, products and variants so draft
merchandise never leaks onto the storefront.  Relationships used by product
cards are eager-loaded to avoid N+1 queries.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import Category, Product, ProductVariant

MAX_RESULTS: Final = 60
MAX_FILTER_LENGTH: Final = 80
MAX_SEARCH_LENGTH: Final = 80

_SIZE_ORDER: Final = {
    "XS": 0,
    "S": 1,
    "M": 2,
    "L": 3,
    "XL": 4,
    "XXL": 5,
    "XXXL": 6,
    "ONE SIZE": 7,
}


@dataclass(frozen=True, slots=True)
class CatalogFilters:
    """Normalized, validated storefront filter values."""

    category: str | None = None
    size: str | None = None
    color: str | None = None
    query: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        category: str | None = None,
        size: str | None = None,
        color: str | None = None,
        q: str | None = None,
    ) -> CatalogFilters:
        """Build filters from untrusted query-string values."""
        return cls(
            category=_clean_value(category, max_length=MAX_FILTER_LENGTH, lowercase=True),
            size=_clean_value(size, max_length=MAX_FILTER_LENGTH),
            color=_clean_value(color, max_length=MAX_FILTER_LENGTH),
            query=_clean_value(q, max_length=MAX_SEARCH_LENGTH),
        )

    @property
    def q(self) -> str | None:
        """Alias used by templates and the ``q`` query-string parameter."""
        return self.query

    @property
    def active_count(self) -> int:
        """Number of filters currently applied."""
        return sum(
            value is not None for value in (self.category, self.size, self.color, self.query)
        )

    def as_query_params(self) -> dict[str, str]:
        """Return only non-empty filters as query-string parameters."""
        values = {
            "category": self.category,
            "size": self.size,
            "color": self.color,
            "q": self.query,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, slots=True)
class CatalogFilterOptions:
    """Available catalog facets derived from active inventory."""

    sizes: tuple[str, ...]
    colors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CatalogPage:
    """A single page of filtered catalog results."""

    products: list[Product]
    total: int
    filters: CatalogFilters
    categories: list[Category]
    sizes: tuple[str, ...]
    colors: tuple[str, ...]

    @property
    def is_truncated(self) -> bool:
        """Whether more products exist than the public result cap allows."""
        return self.total > len(self.products)


def list_categories() -> list[Category]:
    """Return active categories in storefront order."""
    statement = (
        select(Category)
        .where(Category.is_active.is_(True))
        .order_by(Category.position, Category.name, Category.id)
    )
    return list(db.session.scalars(statement).all())


def get_category_by_slug(slug: str) -> Category | None:
    """Return one active category by slug, or ``None``."""
    normalized = _clean_value(slug, max_length=MAX_FILTER_LENGTH, lowercase=True)
    if normalized is None:
        return None

    statement = select(Category).where(
        Category.slug == normalized,
        Category.is_active.is_(True),
    )
    return db.session.scalar(statement)


def list_products(
    filters: CatalogFilters | None = None,
    *,
    limit: int = MAX_RESULTS,
    exclude_product_id: int | None = None,
    category_id: int | None = None,
) -> list[Product]:
    """Return active products matching the supplied filters.

    Results are capped at :data:`MAX_RESULTS`.  A non-positive ``limit`` returns
    an empty list rather than issuing an unbounded query.
    """
    if limit <= 0:
        return []

    resolved_filters = filters or CatalogFilters()
    safe_limit = min(limit, MAX_RESULTS)
    conditions = _filter_conditions(resolved_filters)

    if exclude_product_id is not None:
        conditions.append(Product.id != exclude_product_id)
    if category_id is not None:
        conditions.append(Product.category_id == category_id)

    statement = (
        _product_statement().where(*conditions).order_by(Product.name, Product.id).limit(safe_limit)
    )
    return list(db.session.scalars(statement).unique().all())


def get_catalog_page(filters: CatalogFilters) -> CatalogPage:
    """Return products, facets and the total count for the shop page."""
    conditions = _filter_conditions(filters)
    products = list_products(filters, limit=MAX_RESULTS)

    count_statement = (
        select(func.count(Product.id))
        .select_from(Product)
        .join(Product.category)
        .where(*conditions)
    )
    total = db.session.scalar(count_statement) or 0
    options = get_filter_options()
    categories = list_categories()

    return CatalogPage(
        products=products,
        total=total,
        filters=filters,
        categories=categories,
        sizes=options.sizes,
        colors=options.colors,
    )


def get_filter_options() -> CatalogFilterOptions:
    """Return active variant sizes and colours for filter controls."""
    sizes = db.session.scalars(
        select(ProductVariant.size)
        .join(ProductVariant.product)
        .join(Product.category)
        .where(
            Product.is_active.is_(True),
            Category.is_active.is_(True),
            ProductVariant.is_active.is_(True),
        )
        .distinct()
    ).all()
    colors = db.session.scalars(
        select(ProductVariant.color)
        .join(ProductVariant.product)
        .join(Product.category)
        .where(
            Product.is_active.is_(True),
            Category.is_active.is_(True),
            ProductVariant.is_active.is_(True),
        )
        .distinct()
    ).all()

    return CatalogFilterOptions(
        sizes=tuple(sorted(set(sizes), key=_size_sort_key)),
        colors=tuple(sorted(set(colors))),
    )


def get_product_by_slug(slug: str) -> Product | None:
    """Return one active product with its category, variants and images."""
    normalized = _clean_value(slug, max_length=MAX_FILTER_LENGTH, lowercase=True)
    if normalized is None:
        return None

    statement = _product_statement().where(
        Product.slug == normalized,
        Product.is_active.is_(True),
        Category.is_active.is_(True),
    )
    return db.session.scalars(statement).unique().one_or_none()


def get_related_products(product: Product, *, limit: int = 4) -> list[Product]:
    """Return other active products from the same category."""
    if limit <= 0:
        return []

    return list_products(
        filters=CatalogFilters(category=product.category.slug),
        limit=min(limit, 4),
        exclude_product_id=product.id,
        category_id=product.category_id,
    )


def _product_statement() -> Select[tuple[Product]]:
    """Build the eager-loaded product statement without filters."""
    return (
        select(Product)
        .join(Product.category)
        .options(
            joinedload(Product.category),
            selectinload(Product.variants),
            selectinload(Product.images),
        )
    )


def _filter_conditions(filters: CatalogFilters) -> list:
    """Translate normalized filters into SQLAlchemy conditions."""
    conditions = [
        Product.is_active.is_(True),
        Category.is_active.is_(True),
    ]

    if filters.category is not None:
        conditions.append(Category.slug == filters.category)

    if filters.size is not None:
        conditions.append(
            Product.variants.any(
                and_(
                    ProductVariant.is_active.is_(True),
                    func.lower(ProductVariant.size) == filters.size.lower(),
                )
            )
        )

    if filters.color is not None:
        conditions.append(
            Product.variants.any(
                and_(
                    ProductVariant.is_active.is_(True),
                    func.lower(ProductVariant.color) == filters.color.lower(),
                )
            )
        )

    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                Product.name.ilike(pattern, escape="\\"),
                Product.description.ilike(pattern, escape="\\"),
                Category.name.ilike(pattern, escape="\\"),
            )
        )

    return conditions


def _clean_value(
    value: str | None,
    *,
    max_length: int,
    lowercase: bool = False,
) -> str | None:
    """Strip and length-limit a query-string value without coercing content."""
    if value is None:
        return None

    cleaned = value.strip()
    if not cleaned:
        return None
    if lowercase:
        cleaned = cleaned.lower()
    return cleaned[:max_length]


def _escape_like(value: str) -> str:
    """Escape SQL ``LIKE`` metacharacters so search terms stay literal."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _size_sort_key(size: str) -> tuple[int, int, str]:
    """Sort familiar clothing sizes before unfamiliar ones."""
    normalized = size.strip().upper()
    if normalized in _SIZE_ORDER:
        return (0, _SIZE_ORDER[normalized], normalized)
    if normalized.isdigit():
        return (1, int(normalized), normalized)
    return (2, 0, normalized)
