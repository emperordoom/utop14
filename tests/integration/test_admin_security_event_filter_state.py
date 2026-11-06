"""Tests for server-side admin security-event filter state (B-01 / M14.2 F-02).

Sensitive filters must never appear in a URL, redirect, Referer, cacheable
response, or application log.  The browser holds only an opaque token.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.extensions import db
from app.models import AdminSecurityEventFilterState, SecurityEvent, User
from app.models.security_event import (
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_USER_REQUESTED,
)
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER
from app.services.security_event_admin import AdminSecurityEventFilters
from app.services.security_event_filter_state import (
    FILTER_STATE_COOKIE,
    FilterStateError,
    cleanup_expired_filter_states,
    create_filter_state,
    deserialize_filters,
    generate_token,
    is_valid_token,
    load_filter_state,
    serialize_filters,
    token_digest,
)

PASSWORD = "ValidPass123"
SENSITIVE_HASH = "a" * 64
SENSITIVE_REQUEST_ID = "b" * 32

# Accepted trust boundary (M14.4.1.1 F-01): the application role holds
# SELECT/INSERT/UPDATE/DELETE on admin_security_event_filter_states and there is
# no database-level row isolation.  Cross-admin authorization is enforced at the
# route and service layers; these tests do not claim database isolation.


def _admin(make_user: Callable[..., User], email: str = "filter-admin@example.com") -> User:
    return make_user(email=email, full_name="Filter Admin", role=ROLE_ADMIN)


def _login(client: FlaskClient, csrf_token: Callable[[str], str], email: str) -> None:
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 302


def _add_event(
    *,
    actor_email: str,
    identifier_hash: str | None = SENSITIVE_HASH,
    request_id: str | None = SENSITIVE_REQUEST_ID,
    created_at: datetime | None = None,
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        actor_email=actor_email,
        identifier_hash=identifier_hash,
        ip_address="127.0.0.1",
        user_agent="pytest",
        request_id=request_id,
        metadata_json={},
    )
    if created_at is not None:
        event.created_at = created_at
    db.session.add(event)
    db.session.commit()
    return event


def _form_token(client: FlaskClient, csrf_token: Callable[[str], str]) -> str:
    return csrf_token("/admin/security-events")


def _apply(client: FlaskClient, csrf_token: Callable[[str], str], **filters):
    data: dict[str, object] = {"csrf_token": _form_token(client, csrf_token)}
    data.update(filters)
    return client.post("/admin/security-events/filters", data=data)


# ---------------------------------------------------------------------------
# Token and storage invariants
# ---------------------------------------------------------------------------


def test_token_is_256_bit_urlsafe_and_unique(app: Flask) -> None:
    first = generate_token()
    second = generate_token()
    assert first != second
    assert len(first) == 43
    assert is_valid_token(first)
    assert not is_valid_token("short")
    assert not is_valid_token("!" * 43)


def test_only_the_token_digest_is_stored(app: Flask) -> None:
    admin = User(
        email="digest-admin@example.com",
        full_name="Digest Admin",
        role=ROLE_ADMIN,
    )
    admin.set_password(PASSWORD)
    db.session.add(admin)
    db.session.commit()
    filters = AdminSecurityEventFilters.from_values(
        identifier_hash=SENSITIVE_HASH,
        request_id=SENSITIVE_REQUEST_ID,
    )
    token = create_filter_state(admin.id, filters)

    row = db.session.scalar(select(AdminSecurityEventFilterState))
    assert row is not None
    assert row.token_hash == token_digest(token)
    assert row.token_hash != token
    assert len(row.token_hash) == 64
    assert token not in str(row.filters)


def test_invalid_payload_is_rejected(app: Flask) -> None:
    invalid = AdminSecurityEventFilters.from_values(identifier_hash="not-a-hash")
    with pytest.raises(FilterStateError):
        serialize_filters(invalid)
    assert deserialize_filters({"unknown": "value"}) is None
    assert deserialize_filters({"identifier_hash": 5}) is None
    assert deserialize_filters("not-a-dict") is None


def test_expired_state_is_rejected_before_cleanup(app: Flask) -> None:
    admin = User(email="expiry-admin@example.com", full_name="Expiry", role=ROLE_ADMIN)
    admin.set_password(PASSWORD)
    db.session.add(admin)
    db.session.commit()
    filters = AdminSecurityEventFilters.from_values(event_type="auth.logout")
    start = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
    token = create_filter_state(admin.id, filters, now=start)

    assert load_filter_state(token, admin.id, now=start) is not None
    assert load_filter_state(token, admin.id, now=start + timedelta(minutes=31)) is None
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 1


def test_cleanup_removes_only_expired_states(app: Flask) -> None:
    admin = User(email="cleanup-admin@example.com", full_name="Cleanup", role=ROLE_ADMIN)
    admin.set_password(PASSWORD)
    db.session.add(admin)
    db.session.commit()
    filters = AdminSecurityEventFilters.from_values(event_type="auth.logout")
    start = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
    expired = create_filter_state(admin.id, filters, now=start)
    active = create_filter_state(admin.id, filters, now=start + timedelta(hours=1))

    deleted = cleanup_expired_filter_states(
        limit=10,
        now=start + timedelta(minutes=45),
    )
    assert deleted == 1
    remaining = {
        row.token_hash for row in db.session.scalars(select(AdminSecurityEventFilterState))
    }
    assert token_digest(active) in remaining
    assert token_digest(expired) not in remaining


def test_state_is_scoped_to_the_owning_admin(app: Flask) -> None:
    owner = User(email="owner@example.com", full_name="Owner", role=ROLE_ADMIN)
    other = User(email="other@example.com", full_name="Other", role=ROLE_ADMIN)
    owner.set_password(PASSWORD)
    other.set_password(PASSWORD)
    db.session.add_all([owner, other])
    db.session.commit()
    filters = AdminSecurityEventFilters.from_values(event_type="auth.logout")
    token = create_filter_state(owner.id, filters)

    assert load_filter_state(token, owner.id) is not None
    assert load_filter_state(token, other.id) is None
    assert load_filter_state("A" * 43, owner.id) is None


# ---------------------------------------------------------------------------
# POST-Redirect-GET flow
# ---------------------------------------------------------------------------


def test_post_filters_redirects_to_a_clean_url(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="match@example.com")
    _add_event(actor_email="other@example.com", identifier_hash="c" * 64)
    _login(client, csrf_token, admin.email)

    response = _apply(
        client,
        csrf_token,
        identifier_hash=SENSITIVE_HASH,
        request_id=SENSITIVE_REQUEST_ID,
    )
    assert response.status_code == 303
    location = response.headers["Location"]
    assert location == "/admin/security-events"
    assert "identifier_hash" not in location
    assert "request_id" not in location
    assert FILTER_STATE_COOKIE in response.headers.get("Set-Cookie", "")
    cookie = client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events")
    assert cookie is not None
    assert len(cookie.value) == 43

    html = client.get("/admin/security-events").get_data(as_text=True)
    assert "match@example.com" in html
    assert "other@example.com" not in html


def test_pagination_keeps_filters_without_sensitive_query(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    for index in range(21):
        _add_event(
            actor_email=f"page-{index}@example.com",
            created_at=now - timedelta(minutes=index),
        )
    _login(client, csrf_token, admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303

    first = client.get("/admin/security-events").get_data(as_text=True)
    assert "page=2" in first
    assert "identifier_hash=" not in first
    assert "request_id=" not in first

    second = client.get("/admin/security-events?page=2").get_data(as_text=True)
    assert "page-20@example.com" in second


def test_clear_removes_state_and_cookie(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="clear-match@example.com")
    _add_event(actor_email="clear-other@example.com", identifier_hash="c" * 64)
    _login(client, csrf_token, admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303

    response = client.post(
        "/admin/security-events/filters/clear",
        data={"csrf_token": _form_token(client, csrf_token)},
    )
    assert response.status_code == 303
    assert response.headers["Location"] == "/admin/security-events"
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 0
    html = client.get("/admin/security-events").get_data(as_text=True)
    assert "clear-other@example.com" in html


def test_legacy_query_parameters_are_never_reflected(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)

    response = client.get(
        "/admin/security-events",
        query_string={
            "identifier_hash": SENSITIVE_HASH,
            "request_id": SENSITIVE_REQUEST_ID,
        },
    )
    assert response.status_code == 303
    location = response.headers["Location"]
    assert location == "/admin/security-events"
    assert SENSITIVE_HASH not in location
    assert SENSITIVE_REQUEST_ID not in location
    body = response.get_data(as_text=True)
    assert SENSITIVE_HASH not in body
    assert SENSITIVE_REQUEST_ID not in body


def test_legacy_redirect_preserves_active_filter_state(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    """F-02: a legacy link must not reset the admin's active filter state."""
    admin = _admin(make_user)
    _add_event(actor_email="legacy-match@example.com")
    _add_event(actor_email="legacy-other@example.com", identifier_hash="c" * 64)
    _login(client, csrf_token, admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303

    response = client.get(
        "/admin/security-events",
        query_string={
            "identifier_hash": SENSITIVE_HASH,
            "request_id": SENSITIVE_REQUEST_ID,
        },
    )
    assert response.status_code == 303
    assert response.headers["Location"] == "/admin/security-events"
    assert FILTER_STATE_COOKIE not in response.headers.get("Set-Cookie", "")
    assert SENSITIVE_HASH not in response.get_data(as_text=True)
    assert SENSITIVE_REQUEST_ID not in response.get_data(as_text=True)

    cookie = client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events")
    assert cookie is not None
    assert len(cookie.value) == 43

    html = client.get("/admin/security-events").get_data(as_text=True)
    assert "legacy-match@example.com" in html
    assert "legacy-other@example.com" not in html


def test_another_admin_cannot_use_the_token(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    first_admin = _admin(make_user, email="first-admin@example.com")
    second_admin = _admin(make_user, email="second-admin@example.com")
    _add_event(actor_email="scoped-match@example.com")
    _add_event(actor_email="scoped-other@example.com", identifier_hash="c" * 64)
    _login(client, csrf_token, first_admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303
    stolen = client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events").value

    client.post(
        "/auth/logout",
        data={"csrf_token": csrf_token("/auth/account")},
    )
    _login(client, csrf_token, second_admin.email)
    client.set_cookie(FILTER_STATE_COOKIE, stolen, path="/admin/security-events")

    html = client.get("/admin/security-events").get_data(as_text=True)
    # The foreign state is ignored, so the unfiltered list still shows both.
    assert "scoped-other@example.com" in html


def test_logout_deletes_the_state(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 1

    client.post(
        "/auth/logout",
        data={"csrf_token": csrf_token("/auth/account")},
    )
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 0


def test_login_next_drops_sensitive_filter_parameters(
    app: Flask,
    client: FlaskClient,
) -> None:
    target = f"/admin/security-events?identifier_hash={SENSITIVE_HASH}"
    response = client.get("/auth/login", query_string={"next": target})
    assert response.status_code == 303
    location = response.headers["Location"]
    assert "/auth/login" in location
    assert SENSITIVE_HASH not in location
    assert "identifier_hash" not in location


# ---------------------------------------------------------------------------
# Authorization, CSRF, and headers
# ---------------------------------------------------------------------------


def test_non_admin_cannot_apply_filters(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    customer = make_user(email="filter-customer@example.com", role=ROLE_CUSTOMER)
    _login(client, csrf_token, customer.email)
    response = client.post(
        "/admin/security-events/filters",
        data={
            "csrf_token": csrf_token("/auth/account"),
            "identifier_hash": SENSITIVE_HASH,
        },
    )
    assert response.status_code in {302, 403}


def test_missing_csrf_is_rejected(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)
    response = client.post(
        "/admin/security-events/filters",
        data={"identifier_hash": SENSITIVE_HASH},
    )
    assert response.status_code == 400
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 0


@pytest.mark.parametrize(
    "path",
    [
        "/admin/security-events",
        "/admin/security-events/999999",
        "/admin/security-events?event_type=invalid",
    ],
)
def test_admin_security_headers_are_always_present(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    path: str,
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)
    response = client.get(path)
    assert response.status_code in {200, 303, 404}
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


def test_admin_headers_on_405(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)
    response = client.post("/admin/security-events", data={})
    assert response.status_code == 405
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


def test_admin_headers_on_application_500(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _login(client, csrf_token, admin.email)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "app.admin.security_event_routes.list_security_events",
        _boom,
    )
    previous = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False
    try:
        response = client.get("/admin/security-events")
    finally:
        app.config["PROPAGATE_EXCEPTIONS"] = previous
    assert response.status_code == 500
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Robots-Tag"] == "noindex, nofollow"


def test_sensitive_values_never_reach_application_logs(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    caplog: pytest.LogCaptureFixture,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="log-match@example.com")
    _login(client, csrf_token, admin.email)
    with caplog.at_level(logging.DEBUG):
        assert (
            _apply(
                client,
                csrf_token,
                identifier_hash=SENSITIVE_HASH,
                request_id=SENSITIVE_REQUEST_ID,
            ).status_code
            == 303
        )
        client.get("/admin/security-events")
    assert SENSITIVE_HASH not in caplog.text
    assert SENSITIVE_REQUEST_ID not in caplog.text
