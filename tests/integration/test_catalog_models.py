"""PostgreSQL-backed tests for catalog models and constraints."""

from __future__ import annotations

from decimal import Decimal

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Category, Product, ProductImage, ProductVariant
from app.models.base import validate_image_path


def _category(slug: str = "t-shirts") -> Category:
    return Category(
        name="T-shirts",
        slug=slug,
        description="Heavyweight cotton.",
        icon="images/category-tees.svg",
        position=10,
    )


def _product(category: Category, *, slug: str = "void-tee") -> Product:
    return Product(
        category=category,
        name="Void Tee",
        slug=slug,
        description="An oversized heavyweight tee.",
        price=Decimal("75.00"),
        image_path="images/product-void-tee.svg",
        image_alt="A washed-black t-shirt.",
    )


def test_product_relationships_and_display_helpers(app: Flask) -> None:
    category = _category()
    product = _product(category)
    product.variants = [
        ProductVariant(size="M", color="Washed Black", sku="UT014-VT-WBK-M", stock=4),
        ProductVariant(size="L", color="Washed Black", sku="UT014-VT-WBK-L", stock=0),
        ProductVariant(
            size="XL",
            color="Washed Black",
            sku="UT014-VT-WBK-XL",
            stock=2,
            is_active=False,
        ),
    ]
    product.images = [
        ProductImage(
            image_path="images/product-void-tee.svg",
            alt_text="Front view.",
            position=0,
        ),
        ProductImage(
            image_path="images/product-void-tee-back.svg",
            alt_text="Back view.",
            position=1,
        ),
    ]
    db.session.add(product)
    db.session.commit()

    refreshed = db.session.scalar(select(Product).where(Product.slug == "void-tee"))
    assert refreshed is not None
    assert refreshed.category is category
    assert [variant.sku for variant in refreshed.variants] == [
        "UT014-VT-WBK-M",
        "UT014-VT-WBK-L",
        "UT014-VT-WBK-XL",
    ]
    assert [variant.sku for variant in refreshed.available_variants] == [
        "UT014-VT-WBK-M",
        "UT014-VT-WBK-L",
    ]
    assert refreshed.is_in_stock is True
    assert refreshed.colour_label == "Washed Black"
    assert refreshed.primary_image is not None
    assert refreshed.primary_image.image_path == "images/product-void-tee.svg"
    assert isinstance(refreshed.price, Decimal)


def test_inactive_variants_do_not_make_a_product_in_stock(app: Flask) -> None:
    product = _product(_category())
    product.variants.append(
        ProductVariant(
            size="M",
            color="Washed Black",
            sku="UT014-VT-WBK-M",
            stock=5,
            is_active=False,
        )
    )
    db.session.add(product)
    db.session.commit()

    refreshed = db.session.scalar(select(Product).where(Product.slug == "void-tee"))
    assert refreshed is not None
    assert refreshed.available_variants == []
    assert refreshed.is_in_stock is False
    assert refreshed.colour_label == "Unavailable"


def test_category_slugs_and_names_are_unique(app: Flask) -> None:
    db.session.add(_category())
    db.session.commit()

    duplicate = _category("t-shirts-alternate")
    db.session.add(duplicate)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_product_slugs_and_variant_skus_are_unique(app: Flask) -> None:
    first = _product(_category())
    db.session.add(first)
    db.session.commit()

    duplicate_slug = _product(first.category, slug="void-tee")
    duplicate_slug.name = "Another Tee"
    db.session.add(duplicate_slug)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    other = _product(_category("hoodies"), slug="signal-hoodie")
    other.name = "Signal Hoodie"
    other.image_path = "images/product-signal-hoodie.svg"
    other.variants.append(ProductVariant(size="M", color="Charcoal", sku="UT014-VT-WBK-M", stock=1))
    db.session.add(other)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_variant_combinations_are_unique_per_product(app: Flask) -> None:
    product = _product(_category())
    product.variants.extend(
        [
            ProductVariant(size="M", color="Washed Black", sku="UT014-VT-WBK-M", stock=1),
            ProductVariant(size="M", color="Washed Black", sku="UT014-VT-WBK-M-2", stock=2),
        ]
    )
    db.session.add(product)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_product_price_must_be_non_negative(app: Flask) -> None:
    product = _product(_category())
    product.price = Decimal("-0.01")
    db.session.add(product)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_variant_stock_must_be_non_negative(app: Flask) -> None:
    product = _product(_category())
    product.variants.append(
        ProductVariant(size="M", color="Washed Black", sku="UT014-VT-WBK-M", stock=-1)
    )
    db.session.add(product)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_image_and_category_positions_must_be_non_negative(app: Flask) -> None:
    product = _product(_category())
    product.images.append(
        ProductImage(
            image_path="images/product-void-tee.svg",
            alt_text="Front.",
            position=-1,
        )
    )
    db.session.add(product)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    category = _category()
    category.position = -1
    db.session.add(category)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_category_with_products_cannot_be_deleted(app: Flask) -> None:
    category = _category()
    db.session.add(_product(category))
    db.session.commit()
    category_id = category.id

    db.session.delete(category)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    assert db.session.get(Category, category_id) is not None


def test_deleting_a_product_cascades_to_variants_and_images(app: Flask) -> None:
    category = _category()
    product = _product(category)
    product.variants.append(
        ProductVariant(size="M", color="Washed Black", sku="UT014-VT-WBK-M", stock=4)
    )
    product.images.append(
        ProductImage(image_path="images/product-void-tee.svg", alt_text="Front.", position=0)
    )
    db.session.add(product)
    db.session.commit()
    product_id = product.id
    variant_id = product.variants[0].id
    image_id = product.images[0].id

    db.session.delete(product)
    db.session.commit()

    assert db.session.get(Product, product_id) is None
    assert db.session.get(ProductVariant, variant_id) is None
    assert db.session.get(ProductImage, image_id) is None
    assert db.session.get(Category, category.id) is not None

    db.session.delete(category)
    db.session.commit()
    assert db.session.scalar(select(Category).where(Category.slug == "t-shirts")) is None


@pytest.mark.parametrize(
    "path",
    [
        "/images/product-void-tee.svg",
        "images\\product-void-tee.svg",
        "images/../secret.svg",
        "images/./product-void-tee.svg",
        "product-void-tee.svg",
        "css/home.css",
        "",
    ],
)
def test_image_paths_must_be_relative_and_under_images(path: str) -> None:
    with pytest.raises(ValueError):
        validate_image_path(path)


def test_valid_image_paths_are_preserved(app: Flask) -> None:
    product = _product(_category())
    product.image_path = "images/nested/product-void-tee.svg"
    db.session.add(product)
    db.session.commit()

    refreshed = db.session.scalar(select(Product).where(Product.slug == "void-tee"))
    assert refreshed is not None
    assert refreshed.image_path == "images/nested/product-void-tee.svg"


@pytest.mark.parametrize(
    "icon",
    [
        "/images/category-tees.svg",
        "images\\category-tees.svg",
        "images/../secret.svg",
        "images/./category-tees.svg",
        "css/home.css",
        "",
    ],
)
def test_category_icons_must_be_safe_image_paths(icon: str) -> None:
    with pytest.raises(ValueError):
        Category(
            name="T-shirts",
            slug="t-shirts",
            description="Heavyweight cotton.",
            icon=icon,
            position=0,
        )
