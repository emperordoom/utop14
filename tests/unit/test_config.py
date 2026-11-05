"""Configuration and fail-safe validation tests."""

from __future__ import annotations

import pytest

from app import create_app
from app.config import ConfigurationError, get_config

VALID_TEST_DATABASE_URL = "postgresql+psycopg://localhost:5432/utop14_test"
VALID_PRODUCTION_SECRET = "unit-test-production-secret-key-0123456789"
VALID_SECURITY_EVENT_HASH_KEY = "unit-test-production-security-event-key-0123456789"

# Keep app-creation tests independent of a developer's ambient HMAC key.
pytestmark = pytest.mark.usefixtures("no_ambient_security_event_hash_key")


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
            "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
        },
    )

    assert app.config["DEBUG"] is False
    assert app.config["TESTING"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["REMEMBER_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["WTF_CSRF_ENABLED"] is True
    assert app.config["SECURITY_EVENT_HASH_KEY"] == VALID_SECURITY_EVENT_HASH_KEY


def test_production_rejects_debug_mode() -> None:
    with pytest.raises(ConfigurationError, match="DEBUG"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
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
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
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
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
            },
        )


def test_production_requires_security_event_hash_key() -> None:
    with pytest.raises(ConfigurationError, match="SECURITY_EVENT_HASH_KEY"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": "",
            },
        )


def test_production_rejects_short_security_event_hash_key() -> None:
    with pytest.raises(ConfigurationError, match="32 bytes"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": "too-short",
            },
        )


def test_production_rejects_placeholder_security_event_hash_key() -> None:
    with pytest.raises(ConfigurationError, match="placeholder"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": "CHANGE_ME_SECURITY_EVENT_HASH_KEY",
            },
        )


def test_production_rejects_prefixed_placeholder_security_event_hash_key() -> None:
    with pytest.raises(ConfigurationError, match="placeholder"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": "unit-test-security-event-hash-key-0123456789",
            },
        )


def test_production_rejects_security_event_hash_key_equal_to_secret() -> None:
    with pytest.raises(ConfigurationError, match="distinct"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": VALID_PRODUCTION_SECRET,
            },
        )


def test_production_accepts_valid_security_event_hash_key() -> None:
    app = create_app(
        "production",
        {
            "SECRET_KEY": VALID_PRODUCTION_SECRET,
            "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
            "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
        },
    )

    assert app.config["SECURITY_EVENT_HASH_KEY"] == VALID_SECURITY_EVENT_HASH_KEY


def test_security_event_hash_key_error_does_not_leak_key() -> None:
    weak_key = "short-secret-key-value"

    with pytest.raises(ConfigurationError) as error:
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": weak_key,
            },
        )

    assert weak_key not in str(error.value)


def test_testing_rejects_short_security_event_hash_key() -> None:
    with pytest.raises(ConfigurationError, match="32 bytes"):
        create_app(
            "testing",
            {
                "SECURITY_EVENT_HASH_KEY": "too-short",
            },
        )


def test_testing_configuration_enables_simulated_payments() -> None:
    config = get_config("testing")

    assert config.PAYMENT_PROVIDER == "simulated"
    assert config.PAYMENT_SIMULATION_ENABLED is True
    assert config.PAYMENT_ATTEMPT_TTL_MINUTES == 15


def test_production_rejects_enabled_payment_simulation() -> None:
    with pytest.raises(ConfigurationError, match="PAYMENT_SIMULATION_ENABLED"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "PAYMENT_SIMULATION_ENABLED": True,
            },
        )


def test_production_rejects_simulated_provider() -> None:
    with pytest.raises(ConfigurationError, match="simulated payment provider"):
        create_app(
            "production",
            {
                "SECRET_KEY": VALID_PRODUCTION_SECRET,
                "SQLALCHEMY_DATABASE_URI": VALID_TEST_DATABASE_URL,
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "PAYMENT_PROVIDER": "simulated",
            },
        )


@pytest.mark.parametrize(
    "value",
    [
        0,
        -1,
        -15,
        True,
        False,
        15.0,
        15.9,
        "15",
        "15.0",
        "15.9",
        "",
        "not-a-number",
        None,
    ],
)
def test_invalid_payment_ttl_is_rejected(value: object) -> None:
    with pytest.raises(ConfigurationError, match="PAYMENT_ATTEMPT_TTL_MINUTES"):
        create_app(
            "testing",
            {
                "PAYMENT_ATTEMPT_TTL_MINUTES": value,
            },
        )


def test_valid_payment_ttl_integer_is_accepted() -> None:
    app = create_app(
        "testing",
        {
            "PAYMENT_ATTEMPT_TTL_MINUTES": 30,
        },
    )

    assert app.config["PAYMENT_ATTEMPT_TTL_MINUTES"] == 30


def test_rate_limit_defaults_are_loaded() -> None:
    app = create_app(
        "testing",
        {
            "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
        },
    )

    assert app.config["AUTH_RATE_LIMIT_ENABLED"] is True
    assert app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"] == 900
    assert app.config["AUTH_RATE_LIMIT_BUCKET_TTL_HOURS"] == 48
    assert app.config["AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS"] == (5, 10, 20)
    assert app.config["AUTH_RATE_LIMIT_IP_THRESHOLDS"] == (30, 60)
    assert app.config["AUTH_RATE_LIMIT_COMBINED_THRESHOLDS"] == (10,)


def test_rate_limit_thresholds_must_increase_monotonically() -> None:
    with pytest.raises(ConfigurationError, match="IDENTIFIER_THRESHOLDS"):
        create_app(
            "testing",
            {
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS": (5, 5, 20),
            },
        )


def test_rate_limit_max_failures_must_match_final_threshold() -> None:
    with pytest.raises(ConfigurationError, match="IDENTIFIER_MAX_FAILURES"):
        create_app(
            "testing",
            {
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS": (5, 10, 15),
            },
        )


def test_rate_limit_cooldown_must_not_exceed_scope_maximum() -> None:
    with pytest.raises(ConfigurationError, match="IDENTIFIER_COOLDOWNS"):
        create_app(
            "testing",
            {
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS": (60, 300, 901),
            },
        )


def test_rate_limit_ttl_must_exceed_window_and_maximum_cooldown() -> None:
    with pytest.raises(ConfigurationError, match="BUCKET_TTL_HOURS"):
        create_app(
            "testing",
            {
                "SECURITY_EVENT_HASH_KEY": VALID_SECURITY_EVENT_HASH_KEY,
                "AUTH_RATE_LIMIT_WINDOW_SECONDS": 3600,
                "AUTH_RATE_LIMIT_BUCKET_TTL_HOURS": 1,
            },
        )


def test_rate_limit_policy_can_be_overridden_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "600")
    monkeypatch.setenv("AUTH_RATE_LIMIT_BUCKET_TTL_HOURS", "24")
    monkeypatch.setenv("AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES", "12")
    monkeypatch.setenv("AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS", "4,8,12")
    monkeypatch.setenv("AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS", "30,120,600")
    monkeypatch.setenv("AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS", "600")

    app = create_app("testing")

    assert app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"] == 600
    assert app.config["AUTH_RATE_LIMIT_BUCKET_TTL_HOURS"] == 24
    assert app.config["AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS"] == (4, 8, 12)
    assert app.config["AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS"] == (30, 120, 600)
    assert app.config["AUTH_RATE_LIMIT_IDENTIFIER_MAX_COOLDOWN_SECONDS"] == 600
