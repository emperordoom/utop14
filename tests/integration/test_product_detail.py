"""Integration tests for the product detail route."""

from __future__ import annotations

import re
from decimal import Decimal

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import Category, Product, ProductImage, ProductVariant


def _category(
    slug: str = "t-shirts",
    *,
    name: str = "T-shirts",
    is_active: bool = True,
) -> Category:
    return Category(
        name=name,
        slug=slug,
        description=f"{name} description",
        icon="images/category-tees.svg",
        position=10,
        is_active=is_active,
    )


def _product(
    category: Category,
    *,
    name: str = "Second Tee",
    slug: str = "second-tee",
    price: str = "95.00",
    is_active: bool = True,
) -> Product:
    return Product(
        category=category,
        name=name,
        slug=slug,
        description=f"{name} description",
        price=Decimal(price),
        image_path="images/product-void-tee.svg",
        image_alt=f"{name} image",
        is_active=is_active,
    )


def _t_shirts() -> Category:
    category = db.session.scalar(select(Category).where(Category.slug == "t-shirts"))
    assert category is not None
    return category


def test_product_detail_renders_catalog_record(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    response = client.get("/product/void-tee")

    assert response.status_code == 200
    assert response.mimetype == "text/html"

    html = response.get_data(as_text=True)
    assert "Void Tee" in html
    assert "$75" in html
    assert "$75.00" not in html
    assert "T-shirts / Drop 014" in html
    assert "Washed Black" in html
    assert "In stock and ready to ship" in html
    assert "4 combinations" in html

    for sku in (
        "UT014-VT-WBK-S",
        "UT014-VT-WBK-M",
        "UT014-VT-WBK-L",
        "UT014-VT-WBK-XL",
    ):
        assert sku in html

    assert "Sold out" in html
    assert "variant-list__item--sold-out" in html
    assert "/static/images/product-void-tee.svg" in html
    assert "/static/css/catalog.css" in html


def test_product_detail_exposes_breadcrumbs(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    html = client.get("/product/void-tee").get_data(as_text=True)

    assert 'aria-label="Breadcrumb"' in html
    assert 'href="/shop"' in html
    assert 'href="/shop?category=t-shirts"' in html
    assert 'aria-current="page"' in html


def test_product_detail_lists_related_products_from_the_category(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    db.session.add(_product(_t_shirts(), name="Second Tee", slug="second-tee"))
    db.session.commit()

    html = client.get("/product/void-tee").get_data(as_text=True)

    assert "Keep the" in html
    assert "More from T-shirts" in html
    assert "Second Tee" in html

    reverse_html = client.get("/product/second-tee").get_data(as_text=True)
    assert "More from T-shirts" in reverse_html
    assert "Void Tee" in reverse_html


def test_product_detail_hides_inactive_variants(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    product = _product(_t_shirts())
    product.variants.extend(
        [
            ProductVariant(
                size="M",
                color="Washed Black",
                sku="UT014-SECOND-M",
                stock=3,
            ),
            ProductVariant(
                size="XXXL",
                color="Washed Black",
                sku="UT014-SECOND-XXXL",
                stock=8,
                is_active=False,
            ),
        ]
    )
    db.session.add(product)
    db.session.commit()

    html = client.get("/product/second-tee").get_data(as_text=True)

    assert "UT014-SECOND-M" in html
    assert "UT014-SECOND-XXXL" not in html
    assert "1 combinations" in html


def test_product_detail_orders_gallery_images_by_position(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    product = _product(_t_shirts())
    product.images.extend(
        [
            ProductImage(
                image_path="images/product-signal-hoodie.svg",
                alt_text="Back view.",
                position=1,
            ),
            ProductImage(
                image_path="images/product-void-tee.svg",
                alt_text="Front view.",
                position=0,
            ),
        ]
    )
    db.session.add(product)
    db.session.commit()

    html = client.get("/product/second-tee").get_data(as_text=True)
    gallery = html.split('class="product-gallery__main"')[1]
    main_image = re.search(r'<img\s+src="([^"]+)"', gallery)
    assert main_image is not None
    assert main_image.group(1) == "/static/images/product-void-tee.svg"
    assert "Back view." in html


def test_product_without_variants_is_marked_sold_out(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    db.session.add(_product(_t_shirts()))
    db.session.commit()

    html = client.get("/product/second-tee").get_data(as_text=True)

    assert "Sold out for this drop" in html
    assert "No variants are available right now." in html
    assert "0 combinations" in html


def test_product_detail_rejects_inactive_products(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    db.session.add(_product(_t_shirts(), slug="draft-tee", name="Draft Tee", is_active=False))
    db.session.commit()

    response = client.get("/product/draft-tee")

    assert response.status_code == 404
    assert "This page slipped" in response.get_data(as_text=True)


def test_product_detail_rejects_products_in_inactive_categories(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    archived = _category("archive", name="Archive", is_active=False)
    db.session.add(_product(archived, slug="archive-tee", name="Archive Tee"))
    db.session.commit()

    assert client.get("/product/archive-tee").status_code == 404


def test_product_detail_returns_404_for_unknown_slug(client: FlaskClient) -> None:
    response = client.get("/product/does-not-exist")

    assert response.status_code == 404
    assert "This page slipped" in response.get_data(as_text=True)
