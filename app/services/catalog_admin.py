"""Admin catalog and inventory management services.

Routes enforce the admin role; this module owns validation, normalization,
transaction boundaries and the queries used by the catalog admin screens.
Catalog image paths are stored relative to ``app/static`` and are validated
against the same allow-list used by the SQLAlchemy models, with additional
scheme and URL-encoding rejection for untrusted form input.  Stock changes
return their before/after values for route feedback; a persistent stock audit
log remains a documented follow-up gap rather than part of M8.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Final

from flask_sqlalchemy.pagination import Pagination
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import Category, Product, ProductImage, ProductVariant
from app.models.base import validate_image_path

MAX_CATEGORY_NAME: Final = 80
MAX_CATEGORY_DESCRIPTION: Final = 1_000
MAX_PRODUCT_NAME: Final = 120
MAX_PRODUCT_DESCRIPTION: Final = 5_000
MAX_ICON_PATH: Final = 255
MAX_IMAGE_ALT: Final = 255
MAX_BADGE: Final = 40
MAX_SKU: Final = 64
MAX_SIZE: Final = 20
MAX_COLOR: Final = 40
MAX_STOCK: Final = 1_000_000
MAX_POSITION: Final = 9_999
MAX_FILTER_LENGTH: Final = 80
LOW_STOCK_THRESHOLD: Final = 5

PRODUCT_STATUS_FILTERS: Final = ("active", "inactive")
STOCK_FILTERS: Final = ("out", "low", "healthy")

_SLUG_PATTERN: Final = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SKU_PATTERN: Final = re.compile(r"^[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_PRICE_PATTERN: Final = re.compile(r"^\d{1,10}(?:\.\d{1,2})?$")
_IMAGE_PATH_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]*$")
_IMAGE_SUFFIXES: Final = frozenset({".avif", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"})
_FORBIDDEN_IMAGE_TOKENS: Final = (
    "%",
    "://",
    "\\",
    "data:",
    "file:",
    "javascript:",
    "vbscript:",
)
_MAX_PRICE: Final = Decimal("9999999999.99")


class CatalogAdminError(Exception):
    """Base error for catalog administration operations."""


class CatalogNotFound(CatalogAdminError):
    """Raised when a catalog record does not exist."""


class CatalogValidationError(CatalogAdminError):
    """Raised when submitted catalog values fail validation."""


class CatalogConflictError(CatalogAdminError):
    """Raised when a catalog value conflicts with an existing record."""


@dataclass(frozen=True, slots=True)
class CategorySummary:
    """A category plus product counts for the admin list."""

    category: Category
    product_count: int
    active_product_count: int


@dataclass(frozen=True, slots=True)
class ProductAdminFilters:
    """Normalized admin product-list filters."""

    query: str | None = None
    category_id: int | None = None
    status: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        q: str | None = None,
        category_id: int | str | None = None,
        status: str | None = None,
    ) -> ProductAdminFilters:
        """Build filters from untrusted query-string values."""
        normalized_status = status.strip().lower() if isinstance(status, str) else None
        return cls(
            query=_clean_filter(q),
            category_id=_optional_int(category_id),
            status=normalized_status if normalized_status in PRODUCT_STATUS_FILTERS else None,
        )

    @property
    def active_count(self) -> int:
        """Number of filters currently applied."""
        return sum(value is not None for value in (self.query, self.category_id, self.status))

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {
            "q": self.query,
            "category": str(self.category_id) if self.category_id is not None else None,
            "status": self.status,
        }
        return {key: value for key, value in values.items() if value}


@dataclass(frozen=True, slots=True)
class InventoryFilters:
    """Normalized inventory-list filters."""

    query: str | None = None
    stock_status: str | None = None

    @classmethod
    def from_values(
        cls,
        *,
        q: str | None = None,
        stock_status: str | None = None,
    ) -> InventoryFilters:
        """Build filters from untrusted query-string values."""
        normalized_stock = stock_status.strip().lower() if isinstance(stock_status, str) else None
        return cls(
            query=_clean_filter(q),
            stock_status=normalized_stock if normalized_stock in STOCK_FILTERS else None,
        )

    @property
    def active_count(self) -> int:
        """Number of filters currently applied."""
        return sum(value is not None for value in (self.query, self.stock_status))

    def as_query_params(self) -> dict[str, str]:
        """Return only active filters for pagination links."""
        values = {"q": self.query, "stock": self.stock_status}
        return {key: value for key, value in values.items() if value}


@dataclass(frozen=True, slots=True)
class StockChange:
    """The result of one locked absolute stock adjustment."""

    variant: ProductVariant
    previous_stock: int
    new_stock: int


# ---------------------------------------------------------------------------
# Category operations
# ---------------------------------------------------------------------------


def list_categories_admin() -> list[CategorySummary]:
    """Return every category with total and active product counts."""
    statement = (
        select(
            Category,
            func.count(Product.id),
            func.count(Product.id).filter(Product.is_active.is_(True)),
        )
        .outerjoin(Product, Product.category_id == Category.id)
        .group_by(Category.id)
        .order_by(Category.position, Category.name, Category.id)
    )
    return [
        CategorySummary(
            category=category,
            product_count=product_count,
            active_product_count=active_product_count,
        )
        for category, product_count, active_product_count in db.session.execute(statement).all()
    ]


def list_category_choices() -> list[tuple[int, str]]:
    """Return every category as a select-field choice, including inactive ones."""
    statement = select(Category).order_by(Category.position, Category.name, Category.id)
    categories = db.session.scalars(statement).all()
    return [
        (
            category.id,
            category.name if category.is_active else f"{category.name} (inactive)",
        )
        for category in categories
    ]


def get_category_admin(category_id: int) -> Category | None:
    """Return one category with its related products."""
    statement = (
        select(Category).options(selectinload(Category.products)).where(Category.id == category_id)
    )
    return db.session.scalar(statement)


def create_category(data: object) -> Category:
    """Validate and create a category."""
    values = _category_values(data)
    _ensure_category_unique(values["name"], values["slug"])
    category = Category(**values)
    db.session.add(category)
    _commit("A category with this name or slug already exists.")
    return category


def update_category(category_id: int, data: object) -> Category:
    """Validate and update an existing category."""
    category = db.session.get(Category, category_id)
    if category is None:
        raise CatalogNotFound("Category not found.")

    values = _category_values(data)
    _ensure_category_unique(values["name"], values["slug"], exclude_id=category.id)
    for field, value in values.items():
        setattr(category, field, value)
    _commit("A category with this name or slug already exists.")
    return category


def set_category_active(category_id: int, is_active: bool) -> Category:
    """Activate or deactivate a category without deleting its products."""
    category = db.session.get(Category, category_id)
    if category is None:
        raise CatalogNotFound("Category not found.")

    if category.is_active != is_active:
        category.is_active = is_active
        _commit("The category status could not be updated.")
    return category


def _category_values(data: object) -> dict[str, object]:
    return {
        "name": _clean_required(
            _field(data, "name"), "Category name", max_length=MAX_CATEGORY_NAME, collapse=True
        ),
        "slug": _normalize_slug(_field(data, "slug"), max_length=MAX_CATEGORY_NAME),
        "description": _clean_optional(
            _field(data, "description"),
            "Category description",
            max_length=MAX_CATEGORY_DESCRIPTION,
        ),
        "icon": _normalize_image_path(_field(data, "icon"), "Category icon"),
        "position": _parse_bounded_int(_field(data, "position"), "Position", maximum=MAX_POSITION),
    }


# ---------------------------------------------------------------------------
# Product operations
# ---------------------------------------------------------------------------


def list_products_admin(
    filters: ProductAdminFilters,
    *,
    page: int = 1,
    per_page: int = 20,
) -> Pagination:
    """Return a paginated, filtered product list with eager-loaded relations."""
    conditions = []
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                Product.name.ilike(pattern, escape="\\"),
                Product.variants.any(ProductVariant.sku.ilike(pattern, escape="\\")),
            )
        )
    if filters.category_id is not None:
        conditions.append(Product.category_id == filters.category_id)
    if filters.status == "active":
        conditions.append(Product.is_active.is_(True))
    elif filters.status == "inactive":
        conditions.append(Product.is_active.is_(False))

    statement = (
        select(Product)
        .options(
            joinedload(Product.category),
            selectinload(Product.variants),
            selectinload(Product.images),
        )
        .where(*conditions)
        .order_by(Product.name, Product.id)
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def get_product_admin(product_id: int) -> Product | None:
    """Return one product with its category, variants and gallery images."""
    statement = (
        select(Product)
        .options(
            joinedload(Product.category),
            selectinload(Product.variants),
            selectinload(Product.images),
        )
        .where(Product.id == product_id)
    )
    return db.session.scalar(statement)


def create_product(data: object) -> Product:
    """Validate and create a product."""
    values = _product_values(data)
    _ensure_product_slug_unique(values["slug"])
    product = Product(**values)
    db.session.add(product)
    _commit("A product with this slug already exists.")
    return product


def update_product(product_id: int, data: object) -> Product:
    """Validate and update an existing product."""
    product = db.session.get(Product, product_id)
    if product is None:
        raise CatalogNotFound("Product not found.")

    values = _product_values(data)
    _ensure_product_slug_unique(values["slug"], exclude_id=product.id)
    for field, value in values.items():
        setattr(product, field, value)
    _commit("A product with this slug already exists.")
    return product


def set_product_active(product_id: int, is_active: bool) -> Product:
    """Activate or deactivate a product together with its storefront visibility."""
    product = db.session.get(Product, product_id)
    if product is None:
        raise CatalogNotFound("Product not found.")

    if product.is_active != is_active:
        product.is_active = is_active
        _commit("The product status could not be updated.")
    return product


def _product_values(data: object) -> dict[str, object]:
    category = _resolve_category(_field(data, "category_id"))
    return {
        "category_id": category.id,
        "name": _clean_required(
            _field(data, "name"), "Product name", max_length=MAX_PRODUCT_NAME, collapse=True
        ),
        "slug": _normalize_slug(_field(data, "slug"), max_length=MAX_PRODUCT_NAME),
        "description": _clean_optional(
            _field(data, "description"),
            "Product description",
            max_length=MAX_PRODUCT_DESCRIPTION,
        ),
        "price": _parse_price(_field(data, "price")),
        "image_path": _normalize_image_path(_field(data, "image_path"), "Product image"),
        "image_alt": _clean_optional(
            _field(data, "image_alt"), "Image alt text", max_length=MAX_IMAGE_ALT
        ),
        "badge": _clean_optional(_field(data, "badge"), "Badge", max_length=MAX_BADGE),
    }


def _resolve_category(value: object) -> Category:
    category_id = _parse_bounded_int(value, "Category", minimum=1, maximum=2_147_483_647)
    category = db.session.get(Category, category_id)
    if category is None:
        raise CatalogValidationError("Choose a valid category.")
    return category


# ---------------------------------------------------------------------------
# Variant operations
# ---------------------------------------------------------------------------


def get_variant_admin(variant_id: int) -> ProductVariant | None:
    """Return one variant with its product and category."""
    statement = (
        select(ProductVariant)
        .options(joinedload(ProductVariant.product).joinedload(Product.category))
        .where(ProductVariant.id == variant_id)
    )
    return db.session.scalar(statement)


def create_variant(product_id: int, data: object) -> ProductVariant:
    """Validate and create a variant for one product."""
    product = db.session.get(Product, product_id)
    if product is None:
        raise CatalogNotFound("Product not found.")

    values = _variant_values(data)
    _ensure_variant_sku_unique(values["sku"])
    _ensure_variant_combination_unique(product.id, values["size"], values["color"])
    variant = ProductVariant(product_id=product.id, **values)
    db.session.add(variant)
    _commit("This SKU or size/colour combination already exists.")
    return variant


def update_variant(variant_id: int, data: object) -> ProductVariant:
    """Validate and update a variant under a row lock."""
    values = _variant_values(data)
    try:
        variant = db.session.scalar(
            select(ProductVariant).where(ProductVariant.id == variant_id).with_for_update()
        )
        if variant is None:
            raise CatalogNotFound("Variant not found.")

        _ensure_variant_sku_unique(values["sku"], exclude_id=variant.id)
        _ensure_variant_combination_unique(
            variant.product_id,
            values["size"],
            values["color"],
            exclude_id=variant.id,
        )
        for field, value in values.items():
            setattr(variant, field, value)
        _commit("This SKU or size/colour combination already exists.")
    except CatalogAdminError:
        db.session.rollback()
        raise
    return variant


def set_variant_active(variant_id: int, is_active: bool) -> ProductVariant:
    """Activate or deactivate a variant, controlling storefront purchasability."""
    variant = db.session.get(ProductVariant, variant_id)
    if variant is None:
        raise CatalogNotFound("Variant not found.")

    if variant.is_active != is_active:
        variant.is_active = is_active
        _commit("The variant status could not be updated.")
    return variant


def _variant_values(data: object) -> dict[str, object]:
    return {
        "size": _clean_required(
            _field(data, "size"), "Size", max_length=MAX_SIZE, collapse=True
        ).upper(),
        "color": _clean_required(
            _field(data, "color"), "Colour", max_length=MAX_COLOR, collapse=True
        ),
        "sku": _normalize_sku(_field(data, "sku")),
        "stock": _parse_bounded_int(_field(data, "stock"), "Stock", minimum=0, maximum=MAX_STOCK),
    }


# ---------------------------------------------------------------------------
# Inventory operations
# ---------------------------------------------------------------------------


def list_inventory_admin(
    filters: InventoryFilters,
    *,
    page: int = 1,
    per_page: int = 20,
) -> Pagination:
    """Return a paginated variant inventory list for stock management."""
    conditions = []
    if filters.query is not None:
        pattern = f"%{_escape_like(filters.query)}%"
        conditions.append(
            or_(
                Product.name.ilike(pattern, escape="\\"),
                ProductVariant.sku.ilike(pattern, escape="\\"),
                ProductVariant.color.ilike(pattern, escape="\\"),
            )
        )
    if filters.stock_status == "out":
        conditions.append(ProductVariant.stock == 0)
    elif filters.stock_status == "low":
        conditions.append(ProductVariant.stock.between(1, LOW_STOCK_THRESHOLD))
    elif filters.stock_status == "healthy":
        conditions.append(ProductVariant.stock > LOW_STOCK_THRESHOLD)

    statement = (
        select(ProductVariant)
        .join(ProductVariant.product)
        .options(joinedload(ProductVariant.product).joinedload(Product.category))
        .where(*conditions)
        .order_by(ProductVariant.stock, Product.name, ProductVariant.id)
    )
    return db.paginate(
        statement,
        page=max(1, page),
        per_page=per_page,
        error_out=False,
    )


def adjust_stock(variant_id: int, stock_value: object) -> StockChange:
    """Set an absolute stock value under a row lock and return the change."""
    new_stock = _parse_bounded_int(stock_value, "Stock", minimum=0, maximum=MAX_STOCK)
    try:
        variant = db.session.scalar(
            select(ProductVariant).where(ProductVariant.id == variant_id).with_for_update()
        )
        if variant is None:
            raise CatalogNotFound("Variant not found.")

        previous_stock = variant.stock
        variant.stock = new_stock
        db.session.commit()
    except CatalogAdminError:
        db.session.rollback()
        raise
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise CatalogAdminError("Stock could not be updated. Please try again.") from exc

    return StockChange(
        variant=variant,
        previous_stock=previous_stock,
        new_stock=new_stock,
    )


# ---------------------------------------------------------------------------
# Gallery image operations
# ---------------------------------------------------------------------------


def get_product_image(product_id: int, image_id: int) -> ProductImage | None:
    """Return one gallery image only when it belongs to the requested product."""
    statement = select(ProductImage).where(
        ProductImage.id == image_id,
        ProductImage.product_id == product_id,
    )
    return db.session.scalar(statement)


def create_product_image(product_id: int, data: object) -> ProductImage:
    """Validate and add a gallery image to one product."""
    product = db.session.get(Product, product_id)
    if product is None:
        raise CatalogNotFound("Product not found.")

    values = _image_values(data)
    image = ProductImage(product_id=product.id, **values)
    db.session.add(image)
    _commit("The gallery image could not be saved.")
    return image


def update_product_image(product_id: int, image_id: int, data: object) -> ProductImage:
    """Validate and update a gallery image that belongs to the product."""
    image = get_product_image(product_id, image_id)
    if image is None:
        raise CatalogNotFound("Gallery image not found.")

    values = _image_values(data)
    for field, value in values.items():
        setattr(image, field, value)
    _commit("The gallery image could not be saved.")
    return image


def delete_product_image(product_id: int, image_id: int) -> ProductImage:
    """Delete a gallery image only when it belongs to the product."""
    image = get_product_image(product_id, image_id)
    if image is None:
        raise CatalogNotFound("Gallery image not found.")

    db.session.delete(image)
    _commit("The gallery image could not be deleted.")
    return image


def _image_values(data: object) -> dict[str, object]:
    return {
        "image_path": _normalize_image_path(_field(data, "image_path"), "Image path"),
        "alt_text": _clean_optional(_field(data, "alt_text"), "Alt text", max_length=MAX_IMAGE_ALT),
        "position": _parse_bounded_int(_field(data, "position"), "Position", maximum=MAX_POSITION),
    }


# ---------------------------------------------------------------------------
# Shared validation and persistence helpers
# ---------------------------------------------------------------------------


def _field(data: object, name: str) -> object:
    """Return a plain value from a mapping, form or arbitrary object.

    WTForms exposes fields as attributes (``form.name`` is a ``StringField``),
    so the submitted value must be read from ``field.data`` rather than passing
    the field object into the normalization helpers.
    """
    value = data.get(name) if isinstance(data, dict) else getattr(data, name, None)
    return getattr(value, "data", value)


def _clean_required(
    value: object,
    label: str,
    *,
    max_length: int,
    collapse: bool = False,
) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError(f"{label} is required.")
    cleaned = " ".join(value.split()) if collapse else value.strip()
    if not cleaned:
        raise CatalogValidationError(f"{label} is required.")
    if len(cleaned) > max_length:
        raise CatalogValidationError(f"{label} must be {max_length} characters or fewer.")
    return cleaned


def _clean_optional(value: object, label: str, *, max_length: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CatalogValidationError(f"{label} must be text.")
    cleaned = value.strip()
    if len(cleaned) > max_length:
        raise CatalogValidationError(f"{label} must be {max_length} characters or fewer.")
    return cleaned


def _normalize_slug(value: object, *, max_length: int) -> str:
    cleaned = _clean_required(value, "Slug", max_length=max_length, collapse=True).lower()
    if not _SLUG_PATTERN.fullmatch(cleaned):
        raise CatalogValidationError(
            "Slug must use lowercase letters, numbers and single hyphens only."
        )
    return cleaned


def _normalize_sku(value: object) -> str:
    cleaned = _clean_required(value, "SKU", max_length=MAX_SKU, collapse=True).upper()
    if not _SKU_PATTERN.fullmatch(cleaned):
        raise CatalogValidationError("SKU must use letters, numbers and single hyphens only.")
    return cleaned


def _normalize_image_path(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError(f"{label} is required.")
    cleaned = value.strip()
    if not cleaned:
        raise CatalogValidationError(f"{label} is required.")

    lowered = cleaned.lower()
    if any(token in lowered for token in _FORBIDDEN_IMAGE_TOKENS):
        raise CatalogValidationError(
            f"{label} must be a relative path beneath images/ with no schemes or encoding."
        )
    if not _IMAGE_PATH_PATTERN.fullmatch(cleaned):
        raise CatalogValidationError(
            f"{label} may only contain letters, numbers, spaces, dots, hyphens, "
            "underscores and forward slashes."
        )

    try:
        normalized = validate_image_path(cleaned)
    except ValueError as exc:
        raise CatalogValidationError(f"{label} must be a safe path beneath images/.") from exc

    suffix = PurePosixPath(normalized).suffix.lower()
    if suffix not in _IMAGE_SUFFIXES:
        raise CatalogValidationError(
            f"{label} must use one of: {', '.join(sorted(_IMAGE_SUFFIXES))}."
        )
    return normalized


def _parse_price(value: object) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise CatalogValidationError(
            "Price must be a non-negative amount with at most 2 decimal places."
        )
    raw = str(value).strip()
    if not _PRICE_PATTERN.fullmatch(raw):
        raise CatalogValidationError(
            "Price must be a non-negative amount with at most 2 decimal places."
        )
    try:
        amount = Decimal(raw).quantize(Decimal("0.01"))
    except InvalidOperation as exc:
        raise CatalogValidationError("Price must be a valid amount.") from exc
    if amount > _MAX_PRICE:
        raise CatalogValidationError("Price is too large.")
    return amount


def _parse_bounded_int(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_POSITION,
) -> int:
    if isinstance(value, bool) or value is None:
        raise CatalogValidationError(f"{label} must be a whole number.")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw.isdigit():
            raise CatalogValidationError(f"{label} must be a whole number.")
        parsed = int(raw)
    else:
        raise CatalogValidationError(f"{label} must be a whole number.")

    if parsed < minimum or parsed > maximum:
        raise CatalogValidationError(f"{label} must be between {minimum} and {maximum}.")
    return parsed


def _clean_filter(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:MAX_FILTER_LENGTH]
    return cleaned or None


def _optional_int(value: int | str | None) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if parsed > 0 else None
    return None


def _ensure_category_unique(
    name: str,
    slug: str,
    *,
    exclude_id: int | None = None,
) -> None:
    name_statement = select(Category.id).where(func.lower(Category.name) == name.lower())
    slug_statement = select(Category.id).where(func.lower(Category.slug) == slug.lower())
    if exclude_id is not None:
        name_statement = name_statement.where(Category.id != exclude_id)
        slug_statement = slug_statement.where(Category.id != exclude_id)

    if db.session.scalar(name_statement.limit(1)) is not None:
        raise CatalogConflictError("A category with this name already exists.")
    if db.session.scalar(slug_statement.limit(1)) is not None:
        raise CatalogConflictError("A category with this slug already exists.")


def _ensure_product_slug_unique(slug: str, *, exclude_id: int | None = None) -> None:
    statement = select(Product.id).where(func.lower(Product.slug) == slug.lower())
    if exclude_id is not None:
        statement = statement.where(Product.id != exclude_id)
    if db.session.scalar(statement.limit(1)) is not None:
        raise CatalogConflictError("A product with this slug already exists.")


def _ensure_variant_sku_unique(sku: str, *, exclude_id: int | None = None) -> None:
    statement = select(ProductVariant.id).where(func.lower(ProductVariant.sku) == sku.lower())
    if exclude_id is not None:
        statement = statement.where(ProductVariant.id != exclude_id)
    if db.session.scalar(statement.limit(1)) is not None:
        raise CatalogConflictError("A variant with this SKU already exists.")


def _ensure_variant_combination_unique(
    product_id: int,
    size: str,
    color: str,
    *,
    exclude_id: int | None = None,
) -> None:
    statement = select(ProductVariant.id).where(
        ProductVariant.product_id == product_id,
        func.lower(ProductVariant.size) == size.lower(),
        func.lower(ProductVariant.color) == color.lower(),
    )
    if exclude_id is not None:
        statement = statement.where(ProductVariant.id != exclude_id)
    if db.session.scalar(statement.limit(1)) is not None:
        raise CatalogConflictError(
            "This size and colour combination already exists for the product."
        )


def _escape_like(value: str) -> str:
    """Escape SQL ``LIKE`` metacharacters so searches stay literal."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _commit(conflict_message: str = "The change could not be saved.") -> None:
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise CatalogConflictError(conflict_message) from exc
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise CatalogAdminError("The change could not be saved. Please try again.") from exc
