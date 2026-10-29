"""PostgreSQL-backed tests for the read-only catalog service."""

from __future__ import annotations

from decimal import Decimal

from flask import Flask
from sqlalchemy import select

from app.extensions import db
from app.models import Category, Product, ProductVariant
from app.services.catalog import (
    CatalogFilters,
    get_catalog_page,
    get_category_by_slug,
    get_filter_options,
    get_product_by_slug,
    get_related_products,
    list_categories,
    list_products,
)


def _category(
    slug: str = "t-shirts",
    *,
    name: str = "T-shirts",
    position: int = 10,
    is_active: bool = True,
) -> Category:
    return Category(
        name=name,
        slug=slug,
        description=f"{name} description",
        icon="images/category-tees.svg",
        position=position,
        is_active=is_active,
    )


def _product(
    category: Category,
    *,
    name: str = "Void Tee",
    slug: str = "void-tee",
    description: str = "An oversized heavyweight tee.",
    price: str = "75.00",
    is_active: bool = True,
) -> Product:
    return Product(
        category=category,
        name=name,
        slug=slug,
        description=description,
        price=Decimal(price),
        image_path="images/product-void-tee.svg",
        image_alt=f"{name} image",
        is_active=is_active,
    )


def _variant(
    product: Product,
    *,
    size: str,
    color: str,
    sku: str,
    stock: int = 5,
    is_active: bool = True,
) -> ProductVariant:
    return ProductVariant(
        product=product,
        size=size,
        color=color,
        sku=sku,
        stock=stock,
        is_active=is_active,
    )


def test_list_categories_returns_only_active_categories_in_order(app: Flask) -> None:
    db.session.add_all(
        [
            _category("pants", name="Pants", position=30),
            _category("t-shirts", name="T-shirts", position=10),
            _category("archived", name="Archived", position=20, is_active=False),
        ]
    )
    db.session.commit()

    assert [category.slug for category in list_categories()] == ["t-shirts", "pants"]
    assert get_category_by_slug("  T-SHIRTS  ") is not None
    assert get_category_by_slug("archived") is None
    assert get_category_by_slug("missing") is None


def test_list_products_hides_inactive_products_and_categories(app: Flask) -> None:
    active = _category()
    archived = _category("archived", name="Archived", is_active=False)
    db.session.add_all(
        [
            _product(active, name="Visible Tee", slug="visible-tee"),
            _product(active, name="Draft Tee", slug="draft-tee", is_active=False),
            _product(archived, name="Archived Tee", slug="archived-tee"),
        ]
    )
    db.session.commit()

    products = list_products()

    assert [product.slug for product in products] == ["visible-tee"]
    assert get_product_by_slug("visible-tee") is not None
    assert get_product_by_slug("draft-tee") is None
    assert get_product_by_slug("archived-tee") is None


def test_category_size_and_color_filters_are_normalized(app: Flask) -> None:
    tees = _category()
    hoodies = _category("hoodies", name="Hoodies", position=20)
    tee = _product(tees, name="Void Tee", slug="void-tee")
    tee.variants.append(_variant(tee, size="M", color="Washed Black", sku="UT014-VT-M"))
    hoodie = _product(hoodies, name="Signal Hoodie", slug="signal-hoodie")
    hoodie.variants.append(_variant(hoodie, size="XL", color="Charcoal", sku="UT014-SH-XL"))
    db.session.add_all([tee, hoodie])
    db.session.commit()

    filters = CatalogFilters.from_values(
        category="  HOODIES ",
        size=" xl ",
        color=" CHARCOAL ",
    )
    assert filters.category == "hoodies"
    assert filters.size == "xl"
    assert filters.color == "CHARCOAL"

    products = list_products(filters)
    assert [product.slug for product in products] == ["signal-hoodie"]

    assert list_products(CatalogFilters.from_values(size="M"))[0].slug == "void-tee"
    assert list_products(CatalogFilters.from_values(color="charcoal"))[0].slug == "signal-hoodie"


def test_inactive_variants_are_ignored_by_filters_and_facets(app: Flask) -> None:
    product = _product(_category())
    product.variants.extend(
        [
            _variant(product, size="M", color="Black", sku="UT014-VT-M"),
            _variant(
                product,
                size="XXXL",
                color="Ghost",
                sku="UT014-VT-XXXL",
                is_active=False,
            ),
        ]
    )
    db.session.add(product)
    db.session.commit()

    options = get_filter_options()
    assert options.sizes == ("M",)
    assert options.colors == ("Black",)
    assert list_products(CatalogFilters.from_values(size="XXXL")) == []
    assert list_products(CatalogFilters.from_values(color="Ghost")) == []


def test_search_matches_name_description_and_category(app: Flask) -> None:
    tees = _category()
    hoodies = _category("hoodies", name="Hoodies", position=20)
    db.session.add_all(
        [
            _product(tees, name="Void Tee", slug="void-tee", description="Acid-washed cotton."),
            _product(
                hoodies,
                name="Signal Hoodie",
                slug="signal-hoodie",
                description="Brushed fleece with a structured hood.",
            ),
        ]
    )
    db.session.commit()

    assert [p.slug for p in list_products(CatalogFilters.from_values(q="void"))] == ["void-tee"]
    assert [p.slug for p in list_products(CatalogFilters.from_values(q="structured"))] == [
        "signal-hoodie"
    ]
    assert [p.slug for p in list_products(CatalogFilters.from_values(q="Hoodies"))] == [
        "signal-hoodie"
    ]


def test_search_treats_like_metacharacters_literally(app: Flask) -> None:
    category = _category()
    db.session.add_all(
        [
            _product(category, name="100% Cotton", slug="percent"),
            _product(category, name="Under_score", slug="underscore"),
            _product(category, name="Back\\slash", slug="backslash"),
            _product(category, name="Plain Tee", slug="plain"),
        ]
    )
    db.session.commit()

    assert [p.slug for p in list_products(CatalogFilters.from_values(q="100%"))] == ["percent"]
    assert [p.slug for p in list_products(CatalogFilters.from_values(q="_"))] == ["underscore"]
    assert [p.slug for p in list_products(CatalogFilters.from_values(q="\\"))] == ["backslash"]


def test_catalog_page_counts_and_caps_results_at_sixty(app: Flask) -> None:
    category = _category()
    db.session.add_all(
        [
            _product(
                category,
                name=f"Tee {index:02d}",
                slug=f"tee-{index:02d}",
            )
            for index in range(65)
        ]
    )
    db.session.commit()

    page = get_catalog_page(CatalogFilters())

    assert page.total == 65
    assert len(page.products) == 60
    assert page.is_truncated is True
    assert [category.slug for category in page.categories] == ["t-shirts"]

    assert len(list_products(limit=500)) == 60
    assert list_products(limit=0) == []


def test_related_products_stay_in_category_and_exclude_current(app: Flask) -> None:
    tees = _category()
    hoodies = _category("hoodies", name="Hoodies", position=20)
    products = [_product(tees, name=f"Tee {index}", slug=f"tee-{index}") for index in range(6)]
    products.append(_product(hoodies, name="Hoodie", slug="hoodie"))
    db.session.add_all(products)
    db.session.commit()

    current = db.session.scalar(select(Product).where(Product.slug == "tee-0"))
    assert current is not None

    related = get_related_products(current)

    assert len(related) == 4
    assert all(product.category_id == current.category_id for product in related)
    assert current.id not in {product.id for product in related}
    assert [product.name for product in related] == ["Tee 1", "Tee 2", "Tee 3", "Tee 4"]
