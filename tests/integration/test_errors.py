"""Tests for the branded storefront error page."""

from __future__ import annotations

from flask.testing import FlaskClient


def test_unknown_route_renders_the_branded_404_page(client: FlaskClient) -> None:
    response = client.get("/this-page-does-not-exist")

    assert response.status_code == 404
    assert response.mimetype == "text/html"

    html = response.get_data(as_text=True)
    assert html.lower().startswith("<!doctype html>")
    assert "UTOP14" in html
    assert "404 / Signal lost" in html
    assert "This page slipped" in html
    assert "into the dark." in html
    assert 'href="/shop"' in html
    assert 'href="/"' in html
    assert "/static/css/catalog.css" in html
    assert "http://" not in html
    assert "https://" not in html


def test_branded_404_stylesheet_is_available(client: FlaskClient) -> None:
    assert client.get("/static/css/catalog.css").status_code == 200
