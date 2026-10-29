"""Configuration and fail-safe validation tests."""

from __future__ import annotations

import pytest

from app import create_app
from app.config import ConfigurationError, get_config

VALID_TEST_DATABASE_URL = "postgresql+psycopg://localhost:5432/utop14_test"
VALID_PRODUCTION_SECRET = "unit-test-production-secret-key-0123456789"


def test_supported_configuration_names_are_resolved() -> None:
    assert get_config("development").ENVIRONMENT == "development"
    assert get_config("production").ENVIRONMENT == "production"
    assert get_config("testing").ENVIRONMENT == "testing"


def test_unknown_configuration_name_fails_safely() -> None:
    with pytest.raises(ConfigurationError, match="APP_ENV"):
        get_config("staging")


def test_missing_secret_key_stops_startup() -> None:
    with pytest.raises(ConfigurationError, match="SECRET_KEY"):
        create_app("testing", {"SECRET_KEY": ""})


def test_missing_database_url_stops_startup() -> None:
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        create_app("testing", {"SQLALCHEMY_DATABASE_URI": ""})


def test_non_psycopg_database_url_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        create_app(
            "testing",
            {"SQLALCHEMY_DATABASE_URI": "sqlite:///utop14.db"},
        )


def test_configuration_errors_do_not_leak_database_url() -> None:
    unsafe_url = "postgresql://user:super-secret-password@localhost:5432/utop14"

    with pytest.raises(ConfigurationError) as error:
        create_app("testing", {"SQLALCHEMY_DATABASE_URI": unsafe_url})

    message = str(error.value)
    assert "super-secret-password" not in message
    assert unsafe_url not in message


def test_environment_variables_are_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "development-environment-secret")
    monkeypatch.setenv("DATABASE_URL", VALID_TEST_DATABASE_URL)
    monkeypatch.setenv("FLASK_DEBUG", "0")

    app = create_app("development")

    assert app.config["SECRET_KEY"] == "development-environment-secret"
    assert app.config["SQLALCHEMY_DATABASE_URI"] == VALID_TEST_DATABASE_URL
    assert app.config["DEBUG"] is False


def test_production_configuration_enforces_secure_defaults() -> None:
    app = create_app(
        "production",
        {
            "SECRET_KEY": VALID_PRODUCTION_SECRET,
            "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
        },
    )

    assert app.config["DEBUG"] is False
    assert app.config["TESTING"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["REMEMBER_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_production_rejects_debug_mode() -> None:
    with pytest.raises(ConfigurationError, match="DEBUG"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "DEBUG": True,
            },
        )


def test_production_rejects_insecure_session_cookie() -> None:
    with pytest.raises(ConfigurationError, match="SESSION_COOKIE_SECURE"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SESSION_COOKIE_SECURE": False,
            },
        )


def test_production_rejects_short_secret_key() -> None:
    with pytest.raises(ConfigurationError, match="at least 32"):
        create_app(
            "production",
            {
                "SECRET_KEY": "too-short",
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
            },
        )
