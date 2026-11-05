"""Unit tests for security-event identifier hashing and metadata allowlists."""

from __future__ import annotations

import pytest
from flask import Flask

from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGIN_THROTTLED,
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
        "app.services.security_events._missing_key_warning_emitted",
        False,
    )
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda *args, **_kwargs: errors.append(args),
    )

    assert hash_identifier("user@example.com") is None
    assert errors
    assert "SECURITY_EVENT_HASH_KEY" in str(errors[0])


def test_missing_key_warning_is_emitted_once(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", "")
    monkeypatch.setattr(
        "app.services.security_events._missing_key_warning_emitted",
        False,
    )
    messages: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda *args, **_kwargs: messages.append(args),
    )

    assert hash_identifier("first@example.com") is None
    assert hash_identifier("second@example.com") is None
    assert len(messages) == 1
    assert "SECURITY_EVENT_HASH_KEY" in str(messages[0])


def test_hash_key_is_not_logged(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = "dedicated-test-key-material-0123456789"
    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", key)
    messages: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda *args, **_kwargs: messages.append(args),
    )

    assert hash_identifier("user@example.com") is not None
    assert messages == []
    assert key not in str(messages)


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


def test_throttle_metadata_allowlist_keeps_only_safe_primitives() -> None:
    cleaned = sanitize_metadata(
        SECURITY_EVENT_LOGIN_THROTTLED,
        {
            "scope": "identifier",
            "retry_after_seconds": 60,
            "window_seconds": 900,
            "failure_count": 5,
            "email": "user@example.com",
            "ip": "203.0.113.9",
            "password": "secret",
        },
    )

    assert cleaned == {
        "scope": "identifier",
        "retry_after_seconds": 60,
        "window_seconds": 900,
        "failure_count": 5,
    }


def test_throttle_metadata_rejects_unknown_scope_and_boolean_counts() -> None:
    with pytest.raises(SecurityEventValidationError):
        sanitize_metadata(
            SECURITY_EVENT_LOGIN_THROTTLED,
            {"scope": "unknown"},
        )
    with pytest.raises(SecurityEventValidationError):
        sanitize_metadata(
            SECURITY_EVENT_LOGIN_THROTTLED,
            {"failure_count": True},
        )
