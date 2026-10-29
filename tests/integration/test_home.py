"""Integration tests for the storefront homepage."""

from __future__ import annotations

import re

from flask import Flask
from flask.testing import FlaskClient

from app.catalog.seed import SeedSummary


def test_homepage_returns_server_rendered_html(client: FlaskClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.mimetype == "text/html"

    html = response.get_data(as_text=True)
    assert html.lower().startswith("<!doctype html>")
    assert 'lang="en"' in html


def test_homepage_is_served_by_the_storefront_blueprint(app: Flask) -> None:
    assert "storefront" in app.blueprints

    endpoint, _ = app.url_map.bind("").match("/", method="GET")
    assert endpoint == "storefront.home"


def test_homepage_presents_brand_and_hero(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    assert "UTOP14" in html
    assert "Wear Your Own Reality" in html
    assert 'aria-label="WEAR YOUR OWN REALITY."' in html
    assert "Drop 014" in html
    assert 'class="skip-link"' in html


def test_homepage_contains_all_major_sections(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    for section_id in ("collection", "featured", "categories", "about"):
        assert f'id="{section_id}"' in html

    for heading in ("After Hours", "Four pieces.", "Choose your", "Not for everyone."):
        assert heading in html


def test_homepage_presents_featured_products_and_prices(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    html = client.get("/").get_data(as_text=True)

    for product in ("Void Tee", "Signal Hoodie", "Utility Pant", "Orbit Cap"):
        assert product in html

    for price in ("$75", "$180", "$160", "$55"):
        assert price in html

    for category in ("T-shirts", "Hoodies", "Pants", "Accessories"):
        assert category in html


def test_homepage_renders_navigation_controls(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    assert "data-nav" in html
    assert "data-nav-toggle" in html
    assert 'aria-expanded="false"' in html
    assert 'aria-controls="primary-menu"' in html


def test_homepage_uses_only_local_assets(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)

    assert "http://" not in html
    assert "https://" not in html

    assets = sorted(set(re.findall(r'(?:src|href)="(/static/[^"]+)"', html)))
    assert assets

    for asset in assets:
        response = client.get(asset)
        assert response.status_code == 200, f"Missing static asset: {asset}"


def test_homepage_references_expected_assets(
    client: FlaskClient,
    seeded_catalog: SeedSummary,
) -> None:
    html = client.get("/").get_data(as_text=True)

    expected = (
        "css/tokens.css",
        "css/base.css",
        "css/components.css",
        "css/home.css",
        "js/nav.js",
        "images/favicon.svg",
        "images/hero-drop-014.svg",
        "images/collection-after-hours.svg",
        "images/product-void-tee.svg",
        "images/product-signal-hoodie.svg",
        "images/product-utility-pant.svg",
        "images/product-orbit-cap.svg",
        "images/category-tees.svg",
        "images/category-hoodies.svg",
        "images/category-pants.svg",
        "images/category-accessories.svg",
    )

    for asset in expected:
        assert f"/static/{asset}" in html


def test_homepage_grain_texture_is_referenced_by_css(client: FlaskClient) -> None:
    css = client.get("/static/css/base.css").get_data(as_text=True)

    assert "../images/grain.svg" in css
    assert client.get("/static/images/grain.svg").status_code == 200


def test_health_endpoint_remains_functional(client: FlaskClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
