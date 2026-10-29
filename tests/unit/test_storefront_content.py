"""Tests for the static storefront content model."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.storefront.content import (
    CATEGORIES,
    FEATURED_COLLECTION,
    PRODUCTS,
    format_money,
)


def test_products_have_decimal_prices_and_local_images() -> None:
    assert len(PRODUCTS) == 4

    names = {product.name for product in PRODUCTS}
    assert names == {"Void Tee", "Signal Hoodie", "Utility Pant", "Orbit Cap"}

    for product in PRODUCTS:
        assert isinstance(product.price, Decimal)
        assert product.price > 0
        assert product.image.startswith("images/")
        assert product.image_alt


def test_categories_cover_the_required_shopping_groups() -> None:
    assert [category.name for category in CATEGORIES] == [
        "T-shirts",
        "Hoodies",
        "Pants",
        "Accessories",
    ]

    for category in CATEGORIES:
        assert category.description
        assert category.icon.startswith("images/")
        assert category.href.startswith("#")


def test_featured_collection_describes_drop_014() -> None:
    assert FEATURED_COLLECTION.name == "After Hours"
    assert "014" in FEATURED_COLLECTION.chapter
    assert FEATURED_COLLECTION.image == "images/collection-after-hours.svg"
    assert FEATURED_COLLECTION.image_alt
    assert len(FEATURED_COLLECTION.details) == 3


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (Decimal("75.00"), "$75"),
        (Decimal("180.50"), "$180.50"),
        (Decimal("1234.00"), "$1,234"),
        (Decimal("0.00"), "$0"),
    ],
)
def test_format_money_uses_editorial_price_style(amount: Decimal, expected: str) -> None:
    assert format_money(amount) == expected


def test_format_money_rejects_floating_point_values() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        format_money(75.0)  # type: ignore[arg-type]
