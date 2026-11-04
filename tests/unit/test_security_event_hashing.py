"""Unit tests for security-event identifier hashing and metadata allowlists."""

from __future__ import annotations

import pytest
from flask import Flask

from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
)
from app.services.security_events import (
    SecurityEventValidationError,
    hash_identifier,
    sanitize_metadata,
)


def test_hash_identifier_is_deterministic_for_normalized_email(app: Flask) -> None:
    first = hash_identifier("  User@Example.COM ")
    second = hash_identifier("user@example.com")

    assert first is not None
    assert first == second
    assert len(first) == 64
    assert "user@example.com" not in first


def test_hash_identifier_differs_with_a_different_key(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = hash_identifier("user@example.com")

    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", "different-test-key")
    second = hash_identifier("user@example.com")

    assert first is not None
    assert second is not None
    assert first != second


def test_hash_identifier_missing_key_returns_none_and_is_observable(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors: list[tuple[object, ...]] = []
    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", "")
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda *args, **_kwargs: errors.append(args),
    )

    assert hash_identifier("user@example.com") is None
    assert errors
    assert "SECURITY_EVENT_HASH_KEY" in str(errors[0])


def test_metadata_allowlist_drops_unknown_and_sensitive_keys() -> None:
    cleaned = sanitize_metadata(
        SECURITY_EVENT_LOGIN_SUCCEEDED,
        {
            "auth_method": "password",
            "remember_requested": True,
            "password": "secret",
            "session_id": "abc",
            "email": "user@example.com",
        },
    )

    assert cleaned == {"auth_method": "password", "remember_requested": True}


def test_metadata_rejects_invalid_auth_method() -> None:
    with pytest.raises(SecurityEventValidationError):
        sanitize_metadata(SECURITY_EVENT_LOGIN_FAILED, {"auth_method": "magic"})


def test_metadata_rejects_non_boolean_remember_flag() -> None:
    with pytest.raises(SecurityEventValidationError):
        sanitize_metadata(
            SECURITY_EVENT_LOGIN_SUCCEEDED,
            {"auth_method": "password", "remember_requested": "yes"},
        )


def test_metadata_rejects_unknown_event_type() -> None:
    with pytest.raises(SecurityEventValidationError):
        sanitize_metadata("auth.not_real", {})
