"""Application factory startup tests."""

from __future__ import annotations

import sys

from flask import Flask

from app.extensions import csrf, db, login_manager


def test_application_factory_creates_configured_app(app: Flask) -> None:
    assert isinstance(app, Flask)
    assert app.config["ENVIRONMENT"] == "testing"
    assert app.config["TESTING"] is True
    assert app.config["DEBUG"] is False


def test_extensions_are_initialized(app: Flask) -> None:
    assert app.extensions["sqlalchemy"] is db
    assert app.extensions["migrate"].db is db
    assert app.login_manager is login_manager
    assert app.extensions["csrf"] is csrf


def test_main_blueprint_is_registered(app: Flask) -> None:
    assert "main" in app.blueprints
    endpoint, _ = app.url_map.bind("").match("/health", method="GET")
    assert endpoint == "main.health"


def test_storefront_blueprint_is_registered(app: Flask) -> None:
    assert "storefront" in app.blueprints
    endpoint, _ = app.url_map.bind("").match("/", method="GET")
    assert endpoint == "storefront.home"


def test_models_package_is_imported_for_migrations(app: Flask) -> None:
    assert "app.models" in sys.modules
    assert app.extensions["migrate"].db.metadata is db.metadata


def test_csrf_protection_is_enabled(app: Flask) -> None:
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_session_cookie_defaults_are_hardened(app: Flask) -> None:
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["REMEMBER_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["REMEMBER_COOKIE_SAMESITE"] == "Lax"
