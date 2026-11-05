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
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
ENV_FILE: Final = PROJECT_ROOT / ".env"

_ALLOWED_ENVIRONMENTS: Final = ("development", "production", "testing")
_POSTGRES_PSYCOPG_SCHEME: Final = "postgresql+psycopg://"
_MIN_PRODUCTION_SECRET_LENGTH: Final = 32
_MIN_SECURITY_EVENT_HASH_KEY_BYTES: Final = 32
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
_PLACEHOLDER_SECURITY_EVENT_HASH_KEYS: Final = frozenset(
    {
        "change-me",
        "change_me",
        "change_me_security_event_hash_key",
        "changeme",
        "development",
        "password",
        "production",
        "replace-me",
        "replace_me",
        "secret",
        "test",
        "unit-test-security-event-hash-key",
        "utop14",
        "your-security-event-hash-key",
    }
)
_PLACEHOLDER_SECURITY_EVENT_HASH_KEY_PREFIXES: Final = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
    "unit-test-security-event-hash-key",
    "your-security-event-hash-key",
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


def _env_int(name: str, *, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        return int(raw_value.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a positive integer.") from exc


def _env_int_tuple(
    name: str,
    default: tuple[int, ...],
    *,
    minimum: int = 1,
) -> tuple[int, ...]:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    parts = [part.strip() for part in raw_value.split(",") if part.strip()]
    if not parts:
        raise ConfigurationError(f"{name} must be a comma-separated list of integers.")
    try:
        values = tuple(int(part) for part in parts)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a comma-separated list of integers.") from exc
    if any(value < minimum for value in values):
        raise ConfigurationError(f"{name} must contain only positive integers.")
    return values


def _rate_limit_settings() -> dict[str, object]:
    """Return environment-backed rate-limit settings and approved defaults."""
    return {
        "AUTH_RATE_LIMIT_ENABLED": _env_bool("AUTH_RATE_LIMIT_ENABLED", default=True),
        "AUTH_RATE_LIMIT_WINDOW_SECONDS": _env_int(
            "AUTH_RATE_LIMIT_WINDOW_SECONDS",
            default=900,
        ),
        "AUTH_RATE_LIMIT_BUCKET_TTL_HOURS": _env_int(
            "AUTH_RATE_LIMIT_BUCKET_TTL_HOURS",
            default=48,
        ),
        "AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES": _env_int(
            "AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES",
            default=20,
        ),
        "AUTH_RATE_LIMIT_IP_MAX_FAILURES": _env_int(
            "AUTH_RATE_LIMIT_IP_MAX_FAILURES",
            default=60,
        ),
        "AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES": _env_int(
            "AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES",
            default=10,
        ),
        "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS": _env_int_tuple(
            "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS",
            (5, 10, 20),
        ),
        "AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS": _env_int_tuple(
            "AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS",
            (60, 300, 900),
        ),
        "AUTH_RATE_LIMIT_IP_THRESHOLDS": _env_int_tuple(
            "AUTH_RATE_LIMIT_IP_THRESHOLDS",
            (30, 60),
        ),
        "AUTH_RATE_LIMIT_IP_COOLDOWNS": _env_int_tuple(
            "AUTH_RATE_LIMIT_IP_COOLDOWNS",
            (300, 900),
        ),
        "AUTH_RATE_LIMIT_COMBINED_THRESHOLDS": _env_int_tuple(
            "AUTH_RATE_LIMIT_COMBINED_THRESHOLDS",
            (10,),
        ),
        "AUTH_RATE_LIMIT_COMBINED_COOLDOWNS": _env_int_tuple(
            "AUTH_RATE_LIMIT_COMBINED_COOLDOWNS",
            (300,),
        ),
        "AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS": _env_int(
            "AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS",
            default=900,
        ),
        "AUTH_RATE_LIMIT_IP_MAX_COOLDOWN_SECONDS": _env_int(
            "AUTH_RATE_LIMIT_IP_MAX_COOLDOWN_SECONDS",
            default=1800,
        ),
        "AUTH_RATE_LIMIT_COMBINED_MAX_COOLDOWN_SECONDS": _env_int(
            "AUTH_RATE_LIMIT_COMBINED_MAX_COOLDOWN_SECONDS",
            default=900,
        ),
    }


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

    # Payment configuration.  The simulated provider is development/testing
    # only; production has no real provider in M7.
    PAYMENT_PROVIDER = ""
    PAYMENT_SIMULATION_ENABLED = False
    PAYMENT_ATTEMPT_TTL_MINUTES = 15

    # Avatar uploads are stored outside the application/static tree.  An empty
    # path is resolved to ``<instance>/avatars`` by ``configure_avatar_storage``.
    AVATAR_STORAGE_PATH = ""
    AVATAR_MAX_BYTES = 2 * 1024 * 1024
    AVATAR_MAX_DIMENSION = 2048

    # Manual bank-transfer policy and private evidence storage.
    MANUAL_TRANSFER_TTL_HOURS = 24
    BANK_TRANSFER_BANK_NAME = ""
    BANK_TRANSFER_ACCOUNT_NAME = ""
    BANK_TRANSFER_ACCOUNT_NUMBER = ""
    PAYMENT_PROOF_STORAGE_PATH = ""
    PAYMENT_PROOF_MAX_BYTES = 5 * 1024 * 1024
    PAYMENT_PROOF_MAX_DIMENSION = 4096

    # Only trust X-Forwarded-* headers when the deployment explicitly declares
    # the number of proxy hops in front of the application.  The safe default
    # for local development and direct exposure is zero.
    TRUSTED_PROXY_HOPS = 0

    # Dedicated HMAC key for non-reversible authentication identifier hashes.
    # No raw unknown identifiers are stored when this is unset.
    SECURITY_EVENT_HASH_KEY = ""

    # PostgreSQL-backed fixed-window authentication rate limiting.  Login is
    # not wired to these values until M14.3.2; the foundation owns the policy.
    AUTH_RATE_LIMIT_ENABLED = True
    AUTH_RATE_LIMIT_WINDOW_SECONDS = 900
    AUTH_RATE_LIMIT_BUCKET_TTL_HOURS = 48
    AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES = 20
    AUTH_RATE_LIMIT_IP_MAX_FAILURES = 60
    AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES = 10
    AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS = (5, 10, 20)
    AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS = (60, 300, 900)
    AUTH_RATE_LIMIT_IP_THRESHOLDS = (30, 60)
    AUTH_RATE_LIMIT_IP_COOLDOWNS = (300, 900)
    AUTH_RATE_LIMIT_COMBINED_THRESHOLDS = (10,)
    AUTH_RATE_LIMIT_COMBINED_COOLDOWNS = (300,)
    AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS = 900
    AUTH_RATE_LIMIT_IP_MAX_COOLDOWN_SECONDS = 1800
    AUTH_RATE_LIMIT_COMBINED_MAX_COOLDOWN_SECONDS = 900

    @classmethod
    def load(cls) -> dict[str, Any]:
        """Return the environment-dependent settings for this configuration."""
        settings = {
            "SECRET_KEY": _env_str("SECRET_KEY"),
            "SQLALCHEMY_DATABASE_URI": _env_str("DATABASE_URL"),
            "AVATAR_STORAGE_PATH": _env_str("AVATAR_STORAGE_PATH"),
            "BANK_TRANSFER_BANK_NAME": _env_str("BANK_TRANSFER_BANK_NAME"),
            "BANK_TRANSFER_ACCOUNT_NAME": _env_str("BANK_TRANSFER_ACCOUNT_NAME"),
            "BANK_TRANSFER_ACCOUNT_NUMBER": _env_str("BANK_TRANSFER_ACCOUNT_NUMBER"),
            "PAYMENT_PROOF_STORAGE_PATH": _env_str("PAYMENT_PROOF_STORAGE_PATH"),
            "MANUAL_TRANSFER_TTL_HOURS": _env_int("MANUAL_TRANSFER_TTL_HOURS", default=24),
            "TRUSTED_PROXY_HOPS": _env_int("TRUSTED_PROXY_HOPS", default=0),
            "SECURITY_EVENT_HASH_KEY": _env_str("SECURITY_EVENT_HASH_KEY"),
        }
        settings.update(_rate_limit_settings())
        return settings


class DevelopmentConfig(BaseConfig):
    """Local development settings.

    Cookies are not marked Secure because local development normally runs
    over plain HTTP.  Production enforces the Secure flag.
    """

    ENVIRONMENT = "development"
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    PAYMENT_PROVIDER = "simulated"
    PAYMENT_SIMULATION_ENABLED = True
    PAYMENT_ATTEMPT_TTL_MINUTES = 15

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

    PAYMENT_PROVIDER = ""
    PAYMENT_SIMULATION_ENABLED = False
    PAYMENT_ATTEMPT_TTL_MINUTES = 15


class TestingConfig(BaseConfig):
    """Deterministic test settings.

    ``TEST_DATABASE_URL`` takes precedence.  When it is absent, the configured
    development URL is reused with its database name replaced by
    ``utop14_test`` so tests keep the same credentials and host without ever
    touching ``utop14_db``.  Database tests are guarded by a ``_test`` suffix
    check in :func:`validate_config`.
    """

    ENVIRONMENT = "testing"
    DEBUG = False
    TESTING = True

    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    PREFERRED_URL_SCHEME = "http"

    PAYMENT_PROVIDER = "simulated"
    PAYMENT_SIMULATION_ENABLED = True
    PAYMENT_ATTEMPT_TTL_MINUTES = 15

    @classmethod
    def load(cls) -> dict[str, Any]:
        settings = {
            "SECRET_KEY": _env_str("TEST_SECRET_KEY")
            or "utop14-testing-only-secret-not-for-production",
            "SQLALCHEMY_DATABASE_URI": _test_database_url(),
            "BANK_TRANSFER_BANK_NAME": _env_str("BANK_TRANSFER_BANK_NAME"),
            "BANK_TRANSFER_ACCOUNT_NAME": _env_str("BANK_TRANSFER_ACCOUNT_NAME"),
            "BANK_TRANSFER_ACCOUNT_NUMBER": _env_str("BANK_TRANSFER_ACCOUNT_NUMBER"),
            "PAYMENT_PROOF_STORAGE_PATH": _env_str("PAYMENT_PROOF_STORAGE_PATH"),
            "MANUAL_TRANSFER_TTL_HOURS": _env_int("MANUAL_TRANSFER_TTL_HOURS", default=24),
            "TRUSTED_PROXY_HOPS": _env_int("TRUSTED_PROXY_HOPS", default=0),
            "SECURITY_EVENT_HASH_KEY": _env_str("SECURITY_EVENT_HASH_KEY"),
        }
        settings.update(_rate_limit_settings())
        return settings


def _test_database_url() -> str:
    """Resolve the isolated test database URL without touching development data."""
    explicit_url = _env_str("TEST_DATABASE_URL")
    if explicit_url:
        return explicit_url

    development_url = _env_str("DATABASE_URL")
    fallback_url = "postgresql+psycopg://localhost:5432/utop14_test"
    if not development_url:
        return fallback_url

    try:
        url = make_url(development_url)
    except ArgumentError:
        # Let validate_config report the malformed URL without echoing secrets.
        return development_url

    if url.database and url.database.endswith("_test"):
        return development_url
    return url.set(database="utop14_test").render_as_string(hide_password=False)


def _database_name(database_url: str) -> str:
    """Return the database name without exposing credentials."""
    try:
        return make_url(database_url).database or ""
    except ArgumentError:
        return ""


def _configure_private_storage(
    app: Flask,
    *,
    config_key: str,
    default_dirname: str,
) -> None:
    """Resolve and validate a private storage directory.

    The default is ``<instance>/<default_dirname>``.  Configured paths must not
    point into the application source tree or the static web root, so uploaded
    files can never be served directly by Flask's static handler.
    """
    configured = str(app.config.get(config_key) or "").strip()
    storage = (
        Path(configured).expanduser() if configured else Path(app.instance_path) / default_dirname
    ).resolve()
    app_root = Path(app.root_path).resolve()
    static_root = Path(app.static_folder).resolve() if app.static_folder else None

    if storage == app_root or app_root in storage.parents:
        raise ConfigurationError(f"{config_key} must be outside the application source tree.")
    if static_root is not None and (storage == static_root or static_root in storage.parents):
        raise ConfigurationError(f"{config_key} must be outside the static web root.")

    app.config[config_key] = str(storage)


def configure_avatar_storage(app: Flask) -> None:
    """Resolve and validate the private avatar storage directory."""
    _configure_private_storage(
        app,
        config_key="AVATAR_STORAGE_PATH",
        default_dirname="avatars",
    )


def configure_payment_proof_storage(app: Flask) -> None:
    """Resolve and validate the private payment-proof storage directory."""
    _configure_private_storage(
        app,
        config_key="PAYMENT_PROOF_STORAGE_PATH",
        default_dirname="payment-proofs",
    )


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

    max_avatar_bytes = app.config.get("AVATAR_MAX_BYTES")
    if (
        type(max_avatar_bytes) is not int
        or max_avatar_bytes <= 0
        or max_avatar_bytes > 2 * 1024 * 1024
    ):
        raise ConfigurationError("AVATAR_MAX_BYTES must be between 1 and 2,097,152.")

    max_avatar_dimension = app.config.get("AVATAR_MAX_DIMENSION")
    if (
        type(max_avatar_dimension) is not int
        or max_avatar_dimension < 64
        or max_avatar_dimension > 4096
    ):
        raise ConfigurationError("AVATAR_MAX_DIMENSION must be between 64 and 4,096.")

    manual_ttl = app.config.get("MANUAL_TRANSFER_TTL_HOURS")
    if type(manual_ttl) is not int or manual_ttl <= 0:
        raise ConfigurationError("MANUAL_TRANSFER_TTL_HOURS must be a positive integer.")

    proof_max_bytes = app.config.get("PAYMENT_PROOF_MAX_BYTES")
    if (
        type(proof_max_bytes) is not int
        or proof_max_bytes <= 0
        or proof_max_bytes > 5 * 1024 * 1024
    ):
        raise ConfigurationError("PAYMENT_PROOF_MAX_BYTES must be between 1 and 5,242,880.")

    proof_max_dimension = app.config.get("PAYMENT_PROOF_MAX_DIMENSION")
    if (
        type(proof_max_dimension) is not int
        or proof_max_dimension < 64
        or proof_max_dimension > 4096
    ):
        raise ConfigurationError("PAYMENT_PROOF_MAX_DIMENSION must be between 64 and 4,096.")

    # Only an exact ``int`` is accepted.  ``bool`` is a subclass of ``int`` and
    # floats/strings must never be silently truncated or coerced into an unsafe
    # expiry window.
    raw_ttl = app.config.get("PAYMENT_ATTEMPT_TTL_MINUTES", 15)
    if type(raw_ttl) is not int or raw_ttl <= 0:
        raise ConfigurationError("PAYMENT_ATTEMPT_TTL_MINUTES must be a positive integer.")

    proxy_hops = app.config.get("TRUSTED_PROXY_HOPS")
    if type(proxy_hops) is not int or proxy_hops < 0 or proxy_hops > 5:
        raise ConfigurationError("TRUSTED_PROXY_HOPS must be an integer between 0 and 5.")

    if environment == "testing" and not _database_name(database_url).endswith("_test"):
        raise ConfigurationError("Test database names must end with '_test'.")

    _validate_security_event_hash_key(
        secret_key,
        app,
        required=environment == "production",
    )
    _validate_rate_limit_config(app)

    if environment == "production":
        _validate_production(secret_key, app)


def _validate_security_event_hash_key(
    secret_key: str,
    app: Flask,
    *,
    required: bool,
) -> None:
    """Validate the dedicated identifier-hash key without leaking it."""
    security_event_hash_key = str(app.config.get("SECURITY_EVENT_HASH_KEY") or "").strip()
    if not security_event_hash_key:
        if required:
            raise ConfigurationError("SECURITY_EVENT_HASH_KEY is required in production.")
        return
    if len(security_event_hash_key.encode("utf-8")) < _MIN_SECURITY_EVENT_HASH_KEY_BYTES:
        raise ConfigurationError(
            f"SECURITY_EVENT_HASH_KEY must be at least {_MIN_SECURITY_EVENT_HASH_KEY_BYTES} bytes."
        )
    lowered_key = security_event_hash_key.lower()
    if lowered_key in _PLACEHOLDER_SECURITY_EVENT_HASH_KEYS or lowered_key.startswith(
        _PLACEHOLDER_SECURITY_EVENT_HASH_KEY_PREFIXES
    ):
        raise ConfigurationError("SECURITY_EVENT_HASH_KEY must not use a placeholder value.")
    if security_event_hash_key == secret_key:
        raise ConfigurationError("SECURITY_EVENT_HASH_KEY must be distinct from SECRET_KEY.")


def _validate_rate_limit_config(app: Flask) -> None:
    """Validate rate-limit policy without exposing secrets."""
    enabled = app.config.get("AUTH_RATE_LIMIT_ENABLED")
    if type(enabled) is not bool:
        raise ConfigurationError("AUTH_RATE_LIMIT_ENABLED must be a boolean.")

    window = app.config.get("AUTH_RATE_LIMIT_WINDOW_SECONDS")
    ttl_hours = app.config.get("AUTH_RATE_LIMIT_BUCKET_TTL_HOURS")
    if type(window) is not int or window <= 0:
        raise ConfigurationError("AUTH_RATE_LIMIT_WINDOW_SECONDS must be a positive integer.")
    if type(ttl_hours) is not int or ttl_hours <= 0:
        raise ConfigurationError("AUTH_RATE_LIMIT_BUCKET_TTL_HOURS must be a positive integer.")

    for (
        label,
        max_failures_key,
        thresholds_key,
        cooldowns_key,
        max_cooldown_key,
    ) in (
        (
            "identifier",
            "AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES",
            "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS",
            "AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS",
            "AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS",
        ),
        (
            "IP",
            "AUTH_RATE_LIMIT_IP_MAX_FAILURES",
            "AUTH_RATE_LIMIT_IP_THRESHOLDS",
            "AUTH_RATE_LIMIT_IP_COOLDOWNS",
            "AUTH_RATE_LIMIT_IP_MAX_COOLDOWN_SECONDS",
        ),
        (
            "combined",
            "AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES",
            "AUTH_RATE_LIMIT_COMBINED_THRESHOLDS",
            "AUTH_RATE_LIMIT_COMBINED_COOLDOWNS",
            "AUTH_RATE_LIMIT_COMBINED_MAX_COOLDOWN_SECONDS",
        ),
    ):
        max_failures = app.config.get(max_failures_key)
        thresholds = app.config.get(thresholds_key)
        cooldowns = app.config.get(cooldowns_key)
        max_cooldown = app.config.get(max_cooldown_key)

        if type(max_failures) is not int or max_failures <= 0:
            raise ConfigurationError(f"{max_failures_key} must be a positive integer.")
        if not isinstance(thresholds, tuple) or not thresholds:
            raise ConfigurationError(f"{thresholds_key} must be a non-empty integer list.")
        if not isinstance(cooldowns, tuple) or len(cooldowns) != len(thresholds):
            raise ConfigurationError(f"{cooldowns_key} must contain one duration per threshold.")
        if any(type(value) is not int or value <= 0 for value in thresholds):
            raise ConfigurationError(f"{thresholds_key} must contain only positive integers.")
        if any(type(value) is not int or value <= 0 for value in cooldowns):
            raise ConfigurationError(f"{cooldowns_key} must contain only positive integers.")
        if any(thresholds[index] >= thresholds[index + 1] for index in range(len(thresholds) - 1)):
            raise ConfigurationError(f"{thresholds_key} must increase monotonically.")
        if thresholds[-1] != max_failures:
            raise ConfigurationError(
                f"{max_failures_key} must equal the final threshold in {thresholds_key}."
            )
        if type(max_cooldown) is not int or max_cooldown <= 0:
            raise ConfigurationError(f"{max_cooldown_key} must be a positive integer.")
        if any(value > max_cooldown for value in cooldowns):
            raise ConfigurationError(f"{cooldowns_key} must not exceed {max_cooldown_key}.")
        if ttl_hours * 3600 <= window + max_cooldown:
            raise ConfigurationError(
                "AUTH_RATE_LIMIT_BUCKET_TTL_HOURS must exceed the window plus "
                f"{label} maximum cooldown."
            )


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
    if app.config.get("PAYMENT_SIMULATION_ENABLED"):
        raise ConfigurationError("PAYMENT_SIMULATION_ENABLED must be disabled in production.")
    if str(app.config.get("PAYMENT_PROVIDER") or "").strip().lower() == "simulated":
        raise ConfigurationError("The simulated payment provider cannot be used in production.")
