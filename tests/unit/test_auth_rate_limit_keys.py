"""Unit tests for HMAC rate-limit bucket keys."""

from __future__ import annotations

import pytest
from flask import Flask

from app.services.auth_rate_limit import (
    RateLimitKeyError,
    RateLimitKeyUnavailable,
    combined_bucket_key,
    identifier_bucket_key,
    ip_bucket_key,
)


def _is_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def test_identifier_key_is_deterministic_and_normalized(app: Flask) -> None:
    first = identifier_bucket_key("  User@Example.COM ")
    second = identifier_bucket_key("user@example.com")

    assert first == second
    assert _is_hex_digest(first)
    assert "user@example.com" not in first


def test_scope_and_identifier_domain_separation(app: Flask) -> None:
    identifier = "user@example.com"
    ip = "203.0.113.9"

    assert identifier_bucket_key(identifier) != ip_bucket_key(ip)
    assert identifier_bucket_key(identifier) != combined_bucket_key(ip, identifier)
    assert ip_bucket_key(ip) != combined_bucket_key(ip, identifier)
    assert identifier_bucket_key("first@example.com") != identifier_bucket_key("second@example.com")


def test_ipv4_and_ipv6_are_canonicalized(app: Flask) -> None:
    assert ip_bucket_key("2001:0db8::1") == ip_bucket_key("2001:db8::1")
    assert ip_bucket_key(" 203.0.113.9 ") == ip_bucket_key("203.0.113.9")
    assert ip_bucket_key("203.0.113.9") != ip_bucket_key("203.0.113.10")


def test_combined_key_is_not_ambiguous(app: Flask) -> None:
    first = combined_bucket_key("203.0.113.9", "user@example.com")
    second = combined_bucket_key("203.0.113.10", "user@example.com")
    third = combined_bucket_key("203.0.113.9", "other@example.com")

    assert first != second
    assert first != third
    assert second != third


def test_invalid_identifier_and_ip_are_rejected_without_echoing_input(app: Flask) -> None:
    with pytest.raises(RateLimitKeyError) as identifier_error:
        identifier_bucket_key("")
    with pytest.raises(RateLimitKeyError) as ip_error:
        ip_bucket_key("not-an-ip")

    assert "not-an-ip" not in str(ip_error.value)
    assert "user@example.com" not in str(identifier_error.value)


def test_missing_key_raises_typed_error_and_warns_once(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", "")
    monkeypatch.setattr("app.services.auth_rate_limit._missing_key_warning_emitted", False)
    messages: list[str] = []
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda message, **_kwargs: messages.append(str(message)),
    )

    with pytest.raises(RateLimitKeyUnavailable):
        identifier_bucket_key("user@example.com")
    with pytest.raises(RateLimitKeyUnavailable):
        identifier_bucket_key("user@example.com")

    assert len(messages) == 1
    assert "SECURITY_EVENT_HASH_KEY" in messages[0]
    assert "user@example.com" not in messages[0]
