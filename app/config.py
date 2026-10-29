"""Centralized configuration for the UTOP14 Flask application.

Configuration comes from environment variables.  A local ``.env`` file is
loaded when present, but real environment variables always take precedence.
Validation runs before extensions are initialized so a misconfigured process
fails fast without writing secret values to logs or error responses.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Final

from dotenv import load_dotenv
from flask import Flask

PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
ENV_FILE: Final = PROJECT_ROOT / ".env"

_ALLOWED_ENVIRONMENTS: Final = ("development", "production", "testing")
_POSTGRES_PSYCOPG_SCHEME: Final = "postgresql+psycopg://"
_MIN_PRODUCTION_SECRET_LENGTH: Final = 32
_PLACEHOLDER_SECRET_VALUES: Final = frozenset(
    {
        "change-me",
        "change_me",
        "changeme",
        "replace-me",
        "replace_me",
        "secret",
        "your-secret-key",
    }
)


class ConfigurationError(RuntimeError):
    """Raised when required runtime configuration is missing or unsafe."""


def load_environment() -> None:
    """Load local environment values without overriding the real environment."""
    load_dotenv(dotenv_path=ENV_FILE, override=False)


def _env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_bool(name: str, *, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    value = raw_value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False

    raise ConfigurationError(f"{name} must be a boolean value (true/false).")


class BaseConfig:
    """Settings shared by every environment."""

    ENVIRONMENT = "base"
    DEBUG = False
    TESTING = False

    # Secrets and the database URL are loaded from the environment at runtime.
    SECRET_KEY = ""
    SQLALCHEMY_DATABASE_URI = ""
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Secure defaults for sessions, remember-me cookies and CSRF.
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_NAME = "utop14_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_NAME = "utop14_remember"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    @classmethod
    def load(cls) -> dict[str, Any]:
        """Return the environment-dependent settings for this configuration."""
        return {
            "SECRET_KEY": _env_str("SECRET_KEY"),
            "SQLALCHEMY_DATABASE_URI": _env_str("DATABASE_URL"),
        }


class DevelopmentConfig(BaseConfig):
    """Local development settings.

    Cookies are not marked Secure because local development normally runs
    over plain HTTP.  Production enforces the Secure flag.
    """

    ENVIRONMENT = "development"
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    @classmethod
    def load(cls) -> dict[str, Any]:
        settings = super().load()
        settings["DEBUG"] = _env_bool("FLASK_DEBUG", default=True)
        return settings


class ProductionConfig(BaseConfig):
    """Production settings; debug mode is always disabled."""

    ENVIRONMENT = "production"
    DEBUG = False
    TESTING = False

    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = "https"


class TestingConfig(BaseConfig):
    """Deterministic test settings.

    Tests never inherit the production database URL or secret.  Database-backed
    tests may opt in later through ``TEST_DATABASE_URL``.
    """

    ENVIRONMENT = "testing"
    DEBUG = False
    TESTING = True

    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    @classmethod
    def load(cls) -> dict[str, Any]:
        return {
            "SECRET_KEY": _env_str("TEST_SECRET_KEY")
            or "utop14-testing-only-secret-not-for-production",
            "SQLALCHEMY_DATABASE_URI": _env_str("TEST_DATABASE_URL")
            or "postgresql+psycopg://localhost:5432/utop14_test",
        }


_CONFIGURATIONS: Final = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(config_name: str | None = None) -> type[BaseConfig]:
    """Resolve a configuration class by name or ``APP_ENV``.

    Args:
        config_name: Optional explicit environment name.

    Raises:
        ConfigurationError: If the requested environment is not supported.
    """
    selected = (config_name or os.getenv("APP_ENV", "development")).strip().lower()
    try:
        return _CONFIGURATIONS[selected]
    except KeyError as exc:
        allowed = ", ".join(_ALLOWED_ENVIRONMENTS)
        raise ConfigurationError(f"APP_ENV must be one of: {allowed}.") from exc


def validate_config(app: Flask) -> None:
    """Validate critical configuration without exposing secret values.

    Args:
        app: The Flask application whose configuration should be validated.

    Raises:
        ConfigurationError: If required or security-critical settings are
            missing or incompatible with a production deployment.
    """
    environment = str(app.config.get("ENVIRONMENT", "")).strip().lower()
    if environment not in _ALLOWED_ENVIRONMENTS:
        allowed = ", ".join(_ALLOWED_ENVIRONMENTS)
        raise ConfigurationError(f"ENVIRONMENT must be one of: {allowed}.")

    secret_key = str(app.config.get("SECRET_KEY") or "").strip()
    database_url = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "").strip()

    missing = []
    if not secret_key:
        missing.append("SECRET_KEY")
    if not database_url:
        missing.append("DATABASE_URL")
    if missing:
        raise ConfigurationError(f"Missing required configuration: {', '.join(missing)}.")

    if not database_url.startswith(_POSTGRES_PSYCOPG_SCHEME):
        raise ConfigurationError(
            "DATABASE_URL must use the PostgreSQL Psycopg 3 driver ('postgresql+psycopg://...')."
        )

    if environment == "production":
        _validate_production(secret_key, app)


def _validate_production(secret_key: str, app: Flask) -> None:
    """Enforce production-only security settings."""
    if app.config.get("DEBUG"):
        raise ConfigurationError("DEBUG must be disabled in production.")
    if app.config.get("TESTING"):
        raise ConfigurationError("TESTING must be disabled in production.")
    if len(secret_key) < _MIN_PRODUCTION_SECRET_LENGTH:
        raise ConfigurationError(
            f"SECRET_KEY must be at least {_MIN_PRODUCTION_SECRET_LENGTH} characters in production."
        )
    if secret_key.lower() in _PLACEHOLDER_SECRET_VALUES:
        raise ConfigurationError("SECRET_KEY must not use a placeholder value in production.")
    if not app.config.get("SESSION_COOKIE_SECURE"):
        raise ConfigurationError("SESSION_COOKIE_SECURE must be enabled in production.")
    if not app.config.get("REMEMBER_COOKIE_SECURE"):
        raise ConfigurationError("REMEMBER_COOKIE_SECURE must be enabled in production.")
    if not app.config.get("SESSION_COOKIE_HTTPONLY"):
        raise ConfigurationError("SESSION_COOKIE_HTTPONLY must be enabled in production.")
    if not app.config.get("WTF_CSRF_ENABLED"):
        raise ConfigurationError("WTF_CSRF_ENABLED must be enabled in production.")
