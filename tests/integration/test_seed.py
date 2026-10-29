"""Tests for the deterministic catalog seed and CLI command."""

from __future__ import annotations

from decimal import Decimal

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.catalog.seed import (
    CATEGORY_SEEDS,
    PRODUCT_SEEDS,
    SeedSummary,
    seed_catalog,
)
from app.extensions import db
from app.models import Category, Product, ProductImage, ProductVariant


def _count(model: type) -> int:
    statement = select(func.count()).select_from(model)
    return db.session.scalar(statement) or 0


def test_seed_catalog_creates_the_launch_catalog(app: Flask) -> None:
    summary = seed_catalog()

    assert isinstance(summary, SeedSummary)
    assert summary.categories_created == 4
    assert summary.products_created == 4
    assert summary.variants_created == 14
    assert summary.images_created == 4
    assert summary.created == 26
    assert summary.updated == 0

    assert _count(Category) == 4
    assert _count(Product) == 4
    assert _count(ProductVariant) == 14
    assert _count(ProductImage) == 4

    categories = {category.slug: category for category in db.session.scalars(select(Category))}
    assert categories.keys() == {
        "t-shirts",
        "hoodies",
        "pants",
        "accessories",
    }
    assert categories["t-shirts"].name == "T-shirts"

    products = {product.slug: product for product in db.session.scalars(select(Product))}
    assert products.keys() == {"void-tee", "signal-hoodie", "utility-pant", "orbit-cap"}
    assert products["void-tee"].price == Decimal("75.00")
    assert products["signal-hoodie"].price == Decimal("180.00")
    assert products["utility-pant"].price == Decimal("160.00")
    assert products["orbit-cap"].price == Decimal("55.00")
    assert all(isinstance(product.price, Decimal) for product in products.values())


def test_seed_catalog_includes_sold_out_variants(app: Flask) -> None:
    seed_catalog()

    sold_out_skus = set(
        db.session.scalars(select(ProductVariant.sku).where(ProductVariant.stock == 0))
    )

    assert sold_out_skus == {
        "UT014-VT-WBK-XL",
        "UT014-SH-FCH-XS",
        "UT014-UP-STG-34",
    }


def test_seed_catalog_is_idempotent(app: Flask) -> None:
    first = seed_catalog()
    first_skus = sorted(db.session.scalars(select(ProductVariant.sku)))

    second = seed_catalog()

    assert first.created == 26
    assert second.created == 0
    assert second.updated == 26
    assert _count(Category) == 4
    assert _count(Product) == 4
    assert _count(ProductVariant) == 14
    assert _count(ProductImage) == 4
    assert sorted(db.session.scalars(select(ProductVariant.sku))) == first_skus


def test_seed_catalog_does_not_delete_existing_catalog_records(app: Flask) -> None:
    seed_catalog()
    category = db.session.scalar(select(Category).where(Category.slug == "t-shirts"))
    assert category is not None

    db.session.add(
        Product(
            category=category,
            name="User Tee",
            slug="user-tee",
            description="A hand-created product.",
            price=Decimal("99.00"),
            image_path="images/product-void-tee.svg",
            image_alt="A user-created tee.",
        )
    )
    db.session.commit()

    summary = seed_catalog()

    assert summary.products_created == 0
    assert summary.products_updated == 4
    assert db.session.scalar(select(Product).where(Product.slug == "user-tee")) is not None
    assert _count(Product) == 5


def test_seed_assets_exist_in_the_static_directory(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    for product in PRODUCT_SEEDS:
        assert client.get(f"/static/{product.image_path}").status_code == 200

    for category in CATEGORY_SEEDS:
        assert client.get(f"/static/{category.icon}").status_code == 200


def test_catalog_seed_cli_is_registered_and_idempotent(app: Flask) -> None:
    assert "catalog" in app.cli.commands
    runner = app.test_cli_runner()

    first = runner.invoke(args=["catalog", "seed"])
    assert first.exit_code == 0, first.output
    assert (
        "Catalog seeded: 4 categories, 4 products, 14 variants and 4 images created; "
        "0 existing records refreshed."
    ) in first.output

    second = runner.invoke(args=["catalog", "seed"])
    assert second.exit_code == 0, second.output
    assert (
        "Catalog seeded: 0 categories, 0 products, 0 variants and 0 images created; "
        "26 existing records refreshed."
    ) in second.output
