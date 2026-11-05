"""Integration tests for login abuse protection."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select

from app.extensions import db
from app.models import SecurityEvent
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_THROTTLED,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_REASON_COMBINED_RATE_LIMITED,
    SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
    SECURITY_REASON_IP_RATE_LIMITED,
)
from app.services.auth_rate_limit import (
    RateLimitStoreError,
    get_bucket,
    identifier_bucket_key,
    ip_bucket_key,
)
from app.services.login_abuse import record_login_failure

PASSWORD = "ValidPass123"
EMAIL = "abuse-target@example.com"
UNKNOWN_EMAIL = "abuse-unknown@example.com"


def _login(
    client: FlaskClient,
    token_for,
    *,
    email: str,
    password: str = PASSWORD,
    headers: dict[str, str] | None = None,
):
    return client.post(
        "/auth/login",
        data={
            "csrf_token": token_for("/auth/login"),
            "email": email,
            "password": password,
        },
        headers=headers or {},
    )


def _throttled_events() -> list[SecurityEvent]:
    return list(
        db.session.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == SECURITY_EVENT_LOGIN_THROTTLED)
            .order_by(SecurityEvent.id)
        ).all()
    )


def _csrf_for(client: FlaskClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def _configure_scope_threshold(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    scope: str,
    threshold: int,
    cooldown: int,
) -> None:
    prefix = f"AUTH_RATE_LIMIT_{scope.upper()}"
    monkeypatch.setitem(app.config, f"{prefix}_MAX_FAILURES", threshold)
    monkeypatch.setitem(app.config, f"{prefix}_THRESHOLDS", (threshold,))
    monkeypatch.setitem(app.config, f"{prefix}_COOLDOWNS", (cooldown,))
    monkeypatch.setitem(app.config, f"{prefix}_MAX_COOLDOWN_SECONDS", cooldown)


def test_failures_below_identifier_threshold_do_not_block(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
) -> None:
    make_user(email=EMAIL)

    for _ in range(4):
        response = _login(client, csrf_token, email=EMAIL, password="WrongPass123")
        assert response.status_code == 200

    state = get_bucket("identifier", identifier_bucket_key(EMAIL))
    assert state is not None
    assert state.failure_count == 4
    assert state.blocked_until is None
    assert _throttled_events() == []


def test_identifier_threshold_returns_generic_429_with_retry_after(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email=EMAIL)
    for _ in range(5):
        response = _login(client, csrf_token, email=EMAIL, password="WrongPass123")
        assert response.status_code == 200

    events = _throttled_events()
    assert len(events) == 1
    event = events[0]
    assert event.outcome == SECURITY_OUTCOME_FAILURE
    assert event.reason_code == SECURITY_REASON_IDENTIFIER_RATE_LIMITED
    assert event.identifier_hash is not None
    assert event.metadata_json["scope"] == "identifier"
    assert event.metadata_json["retry_after_seconds"] > 0
    assert event.metadata_json["window_seconds"] == 900
    assert event.metadata_json["failure_count"] == 5
    assert EMAIL not in str(event.metadata_json)

    monkeypatch.setattr(
        "app.models.user.User.verify_password",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("password verification must not run while blocked")
        ),
    )
    blocked = _login(client, csrf_token, email=EMAIL, password="WrongPass123")

    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert blocked.headers["Cache-Control"] == "private, no-store"
    assert blocked.headers["Referrer-Policy"] == "no-referrer"
    assert "Too many sign-in attempts" in blocked.get_data(as_text=True)
    assert "identifier_rate_limited" not in blocked.get_data(as_text=True)
    assert len(_throttled_events()) == 1


def test_known_and_unknown_identifiers_have_the_same_throttle_response(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
) -> None:
    make_user(email=EMAIL)
    for _ in range(5):
        _login(client, csrf_token, email=EMAIL, password="WrongPass123")
    known = _login(client, csrf_token, email=EMAIL, password="WrongPass123")

    for _ in range(5):
        _login(client, csrf_token, email=UNKNOWN_EMAIL, password="WrongPass123")
    unknown = _login(client, csrf_token, email=UNKNOWN_EMAIL, password="WrongPass123")

    assert known.status_code == unknown.status_code == 429
    assert "Too many sign-in attempts" in known.get_data(as_text=True)
    assert "Too many sign-in attempts" in unknown.get_data(as_text=True)


def test_successful_login_resets_identifier_but_not_ip_bucket(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
) -> None:
    make_user(email=EMAIL)
    for _ in range(4):
        response = _login(client, csrf_token, email=EMAIL, password="WrongPass123")
        assert response.status_code == 200

    success = _login(client, csrf_token, email=EMAIL)
    assert success.status_code == 302

    assert get_bucket("identifier", identifier_bucket_key(EMAIL)) is None
    ip_state = get_bucket("ip", ip_bucket_key("127.0.0.1"))
    assert ip_state is not None
    assert ip_state.failure_count == 4


def test_successful_login_does_not_reset_another_identifier(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
) -> None:
    other_email = "abuse-other@example.com"
    make_user(email=EMAIL)
    make_user(email=other_email)
    for _ in range(4):
        _login(client, csrf_token, email=EMAIL, password="WrongPass123")
        _login(client, csrf_token, email=other_email, password="WrongPass123")

    assert _login(client, csrf_token, email=EMAIL).status_code == 302

    assert get_bucket("identifier", identifier_bucket_key(EMAIL)) is None
    other_state = get_bucket("identifier", identifier_bucket_key(other_email))
    assert other_state is not None
    assert other_state.failure_count == 4


def test_store_failure_is_fail_open_and_warning_has_no_pii(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email=EMAIL)
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        app.logger,
        "warning",
        lambda *args, **_kwargs: warnings.append(args),
    )

    def _raise_store_error(*_args, **_kwargs):
        raise RateLimitStoreError("simulated store outage")

    monkeypatch.setattr("app.services.login_abuse.active_cooldown", _raise_store_error)

    response = _login(client, csrf_token, email=EMAIL)

    assert response.status_code == 302
    joined = " ".join(str(message) for message in warnings)
    assert "request_id=" in joined
    assert EMAIL not in joined
    assert PASSWORD not in joined


def test_failure_store_error_does_not_become_throttle(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email=EMAIL)

    def _raise_store_error(*_args, **_kwargs):
        raise RateLimitStoreError("simulated store outage")

    monkeypatch.setattr("app.services.login_abuse.record_failure", _raise_store_error)

    response = _login(client, csrf_token, email=EMAIL, password="WrongPass123")

    assert response.status_code == 200
    assert "Invalid email or password." in response.get_data(as_text=True)


def test_ip_threshold_and_spoofed_forwarded_header_is_ignored(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scope_threshold(app, monkeypatch, scope="ip", threshold=2, cooldown=300)

    for index in range(2):
        response = _login(
            client,
            csrf_token,
            email=f"spoofed-{index}@example.com",
            password="WrongPass123",
            headers={"X-Forwarded-For": f"198.51.100.{index + 1}"},
        )
        assert response.status_code == 200

    blocked = _login(
        client,
        csrf_token,
        email="spoofed-final@example.com",
        password="WrongPass123",
        headers={"X-Forwarded-For": "198.51.100.200"},
    )

    assert blocked.status_code == 429
    ip_state = get_bucket("ip", ip_bucket_key("127.0.0.1"))
    assert ip_state is not None
    assert ip_state.failure_count == 2
    assert any(
        event.reason_code == SECURITY_REASON_IP_RATE_LIMITED for event in _throttled_events()
    )


def test_combined_threshold_is_enforced(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scope_threshold(
        app,
        monkeypatch,
        scope="combined",
        threshold=2,
        cooldown=300,
    )
    for _ in range(2):
        response = _login(
            client,
            csrf_token,
            email=EMAIL,
            password="WrongPass123",
        )
        assert response.status_code == 200

    blocked = _login(client, csrf_token, email=EMAIL, password="WrongPass123")

    assert blocked.status_code == 429
    assert any(
        event.reason_code == SECURITY_REASON_COMBINED_RATE_LIMITED for event in _throttled_events()
    )


def test_concurrent_failure_transitions_are_not_duplicated(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_scope_threshold(
        app,
        monkeypatch,
        scope="combined",
        threshold=100,
        cooldown=300,
    )
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def _record() -> tuple:
        with app.app_context():
            return record_login_failure(EMAIL, now=now)

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _index: _record(), range(10)))

    transitions = [transition for result in results for transition in result]
    assert len(transitions) == 1
    assert transitions[0].scope == "identifier"


def test_constrained_pool_login_and_throttle_do_not_leak_connections(
    constrained_pool_app: Flask,
) -> None:
    client = constrained_pool_app.test_client()

    for _ in range(5):
        response = client.post(
            "/auth/login",
            data={
                "csrf_token": _csrf_for(client, "/auth/login"),
                "email": "pool-throttle@example.com",
                "password": "WrongPass123",
            },
        )
        assert response.status_code == 200

    blocked = client.post(
        "/auth/login",
        data={
            "csrf_token": _csrf_for(client, "/auth/login"),
            "email": "pool-throttle@example.com",
            "password": "WrongPass123",
        },
    )

    assert blocked.status_code == 429
    with constrained_pool_app.app_context():
        assert db.engine.pool.checkedout() == 0


def test_throttle_does_not_change_csrf_or_account_security(
    app: Flask,
    client: FlaskClient,
    csrf_token,
    make_user,
) -> None:
    make_user(email=EMAIL)
    for _ in range(5):
        _login(client, csrf_token, email=EMAIL, password="WrongPass123")

    assert _login(client, csrf_token, email=EMAIL, password="WrongPass123").status_code == 429
    assert client.get("/auth/account").status_code == 302
