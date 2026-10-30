"""Integration tests for the filterable shop route."""

from __future__ import annotations

from decimal import Decimal

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import Category, Product


def _product(category: Category, *, name: str, slug: str, is_active: bool = True) -> Product:
    return Product(
        category=category,
        name=name,
        slug=slug,
        description=f"{name} description",
        price=Decimal("99.00"),
        image_path="images/product-void-tee.svg",
        image_alt=f"{name} image",
        is_active=is_active,
    )


def test_shop_lists_the_launch_catalog(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    response = client.get("/shop")

    assert response.status_code == 200
    assert response.mimetype == "text/html"

    html = response.get_data(as_text=True)
    assert "Shop the" in html
    assert "4 pieces" in html
    assert 'aria-live="polite"' in html

    for product in ("Void Tee", "Signal Hoodie", "Utility Pant", "Orbit Cap"):
        assert product in html

    for category in ("T-shirts", "Hoodies", "Pants", "Accessories"):
        assert category in html

    for price in ("Rp 75", "Rp 180", "Rp 160", "Rp 55"):
        assert price in html


def test_shop_references_the_catalog_stylesheet(client: FlaskClient) -> None:
    html = client.get("/shop").get_data(as_text=True)

    assert "/static/css/catalog.css" in html
    assert client.get("/static/css/catalog.css").status_code == 200


def test_shop_filters_by_category(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    response = client.get("/shop", query_string={"category": "t-shirts"})

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Void Tee" in html
    assert "Signal Hoodie" not in html
    assert "1 piece" in html
    assert "1 active filter" in html
    assert 'value="t-shirts" selected' in html


def test_shop_filters_by_size_and_colour(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    size_html = client.get("/shop", query_string={"size": "M"}).get_data(as_text=True)
    assert "Void Tee" in size_html
    assert "Signal Hoodie" in size_html
    assert "Utility Pant" not in size_html
    assert "Orbit Cap" not in size_html

    colour_html = client.get(
        "/shop",
        query_string={"color": "Faded Charcoal"},
    ).get_data(as_text=True)
    assert "Signal Hoodie" in colour_html
    assert "Void Tee" not in colour_html
    assert 'value="Faded Charcoal" selected' in colour_html

    lowercase_html = client.get(
        "/shop",
        query_string={"size": "m", "color": "faded charcoal"},
    ).get_data(as_text=True)
    assert 'value="M" selected' in lowercase_html
    assert 'value="Faded Charcoal" selected' in lowercase_html


def test_shop_search_matches_product_copy(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    void_html = client.get("/shop", query_string={"q": "void"}).get_data(as_text=True)
    assert "Void Tee" in void_html
    assert "Signal Hoodie" not in void_html

    signal_html = client.get("/shop", query_string={"q": "signal"}).get_data(as_text=True)
    assert "Signal Hoodie" in signal_html
    assert "Void Tee" not in signal_html


def test_shop_shows_an_empty_state_for_unmatched_filters(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    response = client.get("/shop", query_string={"size": "XXL"})

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "0 pieces" in html
    assert "Nothing matches that combination." in html
    assert "Reset the catalog" in html


def test_shop_hides_inactive_products_and_categories(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    category = db.session.scalar(select(Category).where(Category.slug == "t-shirts"))
    assert category is not None

    db.session.add_all(
        [
            _product(category, name="Draft Tee", slug="draft-tee", is_active=False),
            Category(
                name="Vault",
                slug="vault",
                description="Retired pieces.",
                icon="images/category-tees.svg",
                position=99,
                is_active=False,
            ),
        ]
    )
    db.session.commit()

    html = client.get("/shop").get_data(as_text=True)
    assert "Draft Tee" not in html
    assert "Vault" not in html


def test_shop_rejects_unknown_and_inactive_categories(
    app: Flask,
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    assert client.get("/shop", query_string={"category": "missing"}).status_code == 404

    db.session.add(
        Category(
            name="Vault",
            slug="vault",
            description="Retired pieces.",
            icon="images/category-tees.svg",
            position=99,
            is_active=False,
        )
    )
    db.session.commit()

    assert client.get("/shop", query_string={"category": "vault"}).status_code == 404


def test_shop_notes_when_results_exceed_the_sixty_item_cap(app: Flask, client: FlaskClient) -> None:
    category = Category(
        name="Archive",
        slug="archive",
        description="Long-run pieces.",
        icon="images/category-tees.svg",
        position=10,
    )
    db.session.add(category)

    for index in range(65):
        db.session.add(
            _product(
                category,
                name=f"Archive Tee {index:02d}",
                slug=f"archive-tee-{index:02d}",
            )
        )
    db.session.commit()

    response = client.get("/shop")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "65 pieces" in html
    assert html.count('class="product-card"') == 60
    assert "Showing the first 60 pieces." in html
