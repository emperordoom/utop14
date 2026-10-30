"""Tests for editorial content and deterministic catalog seed definitions."""

from __future__ import annotations

from decimal import Decimal

from app.catalog.seed import CATEGORY_SEEDS, PRODUCT_SEEDS
from app.storefront.content import FEATURED_COLLECTION


def test_seed_products_have_decimal_prices_and_local_images() -> None:
    assert len(PRODUCT_SEEDS) == 4

    names = {product.name for product in PRODUCT_SEEDS}
    assert names == {"Void Tee", "Signal Hoodie", "Utility Pant", "Orbit Cap"}

    for product in PRODUCT_SEEDS:
        assert isinstance(product.price, Decimal)
        assert product.price > 0
        assert product.image_path.startswith("images/")
        assert product.image_alt


def test_seed_categories_cover_the_required_shopping_groups() -> None:
    assert [category.name for category in CATEGORY_SEEDS] == [
        "T-shirts",
        "Hoodies",
        "Pants",
        "Accessories",
    ]

    positions = [category.position for category in CATEGORY_SEEDS]
    assert positions == sorted(positions)
    assert len(set(positions)) == len(positions)

    for category in CATEGORY_SEEDS:
        assert category.description
        assert category.icon.startswith("images/")


def test_seed_variants_are_unique_and_include_sold_out_inventory() -> None:
    variants = [variant for product in PRODUCT_SEEDS for variant in product.variants]

    assert len(variants) == 14
    assert len({variant.sku for variant in variants}) == len(variants)
    assert all(variant.stock >= 0 for variant in variants)
    assert any(variant.stock == 0 for variant in variants)


def test_featured_collection_describes_drop_014() -> None:
    assert FEATURED_COLLECTION.name == "After Hours"
    assert "014" in FEATURED_COLLECTION.chapter
    assert FEATURED_COLLECTION.image == "images/collection-after-hours.svg"
    assert FEATURED_COLLECTION.image_alt
    assert len(FEATURED_COLLECTION.details) == 3
