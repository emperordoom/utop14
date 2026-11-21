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
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.security_event_admin import AdminSecurityEventFilters
from app.services.security_event_filter_state import (
    _MAX_ACTIVE_STATES_PER_ADMIN,
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


def _extract_csrf(client: FlaskClient, path: str) -> str:
    import re

    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def test_another_admin_cannot_use_the_token(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    """F-B01-04: active foreign admin token must be ignored without logging out owner."""
    first_admin = _admin(make_user, email="first-admin@example.com")
    second_admin = _admin(make_user, email="second-admin@example.com")
    _add_event(actor_email="scoped-match@example.com")
    _add_event(actor_email="scoped-other@example.com", identifier_hash="c" * 64)

    first_client = app.test_client()
    second_client = app.test_client()

    _login(first_client, lambda p: _extract_csrf(first_client, p), first_admin.email)
    assert (
        _apply(
            first_client,
            lambda p: _extract_csrf(first_client, p),
            identifier_hash=SENSITIVE_HASH,
        ).status_code
        == 303
    )
    stolen_cookie = first_client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events")
    assert stolen_cookie is not None
    stolen = stolen_cookie.value

    # First admin stays logged in and the state row remains active in PostgreSQL.
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 1
    assert load_filter_state(stolen, first_admin.id) is not None

    # Clear Flask-Login and Flask-WTF app-context caches before simulating a
    # second independent browser client inside the shared pytest app context.
    from flask import g

    g.pop("_login_user", None)
    g.pop("csrf_token", None)
    _login(second_client, lambda p: _extract_csrf(second_client, p), second_admin.email)
    second_client.set_cookie(FILTER_STATE_COOKIE, stolen, path="/admin/security-events")

    g.pop("_login_user", None)
    g.pop("csrf_token", None)
    second_html = second_client.get("/admin/security-events").get_data(as_text=True)
    # The active foreign state is ignored, so second admin sees the unfiltered list.
    assert "scoped-other@example.com" in second_html
    assert "scoped-match@example.com" in second_html

    # Confirm the owner's active state still works and was untouched.
    g.pop("_login_user", None)
    g.pop("csrf_token", None)
    first_html = first_client.get("/admin/security-events").get_data(as_text=True)
    assert "scoped-match@example.com" in first_html
    assert "scoped-other@example.com" not in first_html


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
    target = (
        f"/admin/security-events?event_type=auth.logout&outcome=success"
        f"&reason=user_requested&date_from=2026-11-01&date_to=2026-11-06"
        f"&request_id={SENSITIVE_REQUEST_ID}&identifier_hash={SENSITIVE_HASH}"
        f"&actor_user_id=42&subject_user_id=99&page=2"
    )
    response = client.get("/auth/login", query_string={"next": target})
    assert response.status_code == 303
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    location = response.headers["Location"]
    assert "/auth/login" in location
    assert "page%3D2" in location or "page=2" in location
    for forbidden in (
        "event_type",
        "outcome",
        "reason",
        "date_from",
        "date_to",
        "request_id",
        "identifier_hash",
        "actor_user_id",
        "subject_user_id",
        SENSITIVE_HASH,
        SENSITIVE_REQUEST_ID,
    ):
        assert forbidden not in location


def test_unauthenticated_legacy_admin_redirect_strips_all_sensitive_params(
    app: Flask,
    client: FlaskClient,
    make_user: Callable[..., User],
) -> None:
    """F-B01-01: unauthenticated 302 redirect must never leak legacy filter params."""
    admin = _admin(make_user)
    response = client.get(
        "/admin/security-events",
        query_string={
            "event_type": "auth.logout",
            "outcome": "success",
            "reason": "user_requested",
            "date_from": "2026-11-01",
            "date_to": "2026-11-06",
            "request_id": SENSITIVE_REQUEST_ID,
            "identifier_hash": SENSITIVE_HASH,
            "actor_user_id": "42",
            "subject_user_id": "99",
            "page": "2",
        },
    )
    assert response.status_code == 302
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    location = response.headers["Location"]
    assert location.startswith("/auth/login")
    for forbidden in (
        "event_type",
        "outcome",
        "reason",
        "date_from",
        "date_to",
        "request_id",
        "identifier_hash",
        "actor_user_id",
        "subject_user_id",
        SENSITIVE_HASH,
        SENSITIVE_REQUEST_ID,
    ):
        assert forbidden not in location
    assert "page%3D2" in location or "page=2" in location

    # Login page renders clean hidden next field and non-cacheable headers.
    login_page = client.get(location)
    assert login_page.status_code == 200
    assert login_page.headers["Cache-Control"] == "private, no-store"
    assert login_page.headers["Referrer-Policy"] == "no-referrer"
    login_html = login_page.get_data(as_text=True)
    assert 'value="/admin/security-events?page=2"' in login_html
    assert SENSITIVE_HASH not in login_html
    assert "actor_user_id" not in login_html

    # Signing in redirects cleanly to /admin/security-events?page=2 without leakage.
    post_response = client.post(
        "/auth/login",
        data={
            "csrf_token": _extract_csrf(client, location),
            "email": admin.email,
            "password": PASSWORD,
            "next": "/admin/security-events?page=2",
        },
    )
    assert post_response.status_code == 302
    assert post_response.headers["Cache-Control"] == "private, no-store"
    assert post_response.headers["Referrer-Policy"] == "no-referrer"
    assert post_response.headers["Location"] == "/admin/security-events?page=2"


def test_login_next_drops_url_encoded_and_mixed_case_sensitive_params(
    app: Flask,
    client: FlaskClient,
) -> None:
    """URL-encoded and mixed-case sensitive params in next must be stripped."""
    encoded_target = (
        f"/admin/security-events?identifier%5Fhash={SENSITIVE_HASH}"
        f"&Actor%5FUser%5FId=42&REQUEST_ID={SENSITIVE_REQUEST_ID}&page=3"
    )
    response = client.get("/auth/login", query_string={"next": encoded_target})
    assert response.status_code == 303
    location = response.headers["Location"]
    assert SENSITIVE_HASH not in location
    assert SENSITIVE_REQUEST_ID not in location
    assert "identifier" not in location.lower()
    assert "actor" not in location.lower()
    assert "request_id" not in location.lower()
    assert "page%3D3" in location or "page=3" in location


def test_login_post_sanitizes_sensitive_next_before_redirect(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": admin.email,
            "password": PASSWORD,
            "next": (
                f"/admin/security-events?identifier_hash={SENSITIVE_HASH}"
                "&actor_user_id=7&subject_user_id=8&page=2"
            ),
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/admin/security-events?page=2"


def test_replacing_filter_state_deletes_previous_state_and_enforces_cap(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    """F-B01-02: applying a new filter replaces the prior row and caps per-admin rows."""
    admin = _admin(make_user, email="replace-admin@example.com")
    other_admin = _admin(make_user, email="other-cap-admin@example.com")
    _login(client, csrf_token, admin.email)

    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303
    first_cookie = client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events")
    assert first_cookie is not None
    first_token = first_cookie.value

    assert _apply(client, csrf_token, request_id=SENSITIVE_REQUEST_ID).status_code == 303
    second_cookie = client.get_cookie(FILTER_STATE_COOKIE, path="/admin/security-events")
    assert second_cookie is not None
    second_token = second_cookie.value
    assert second_token != first_token

    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 1
    assert load_filter_state(first_token, admin.id) is None
    assert load_filter_state(second_token, admin.id) is not None

    # Per-admin cap trims oldest rows for admin without touching other_admin's state.
    other_filters = AdminSecurityEventFilters.from_values(event_type="auth.logout")
    other_token = create_filter_state(other_admin.id, other_filters)
    for _ in range(_MAX_ACTIVE_STATES_PER_ADMIN + 5):
        create_filter_state(admin.id, other_filters)

    admin_count = db.session.scalar(
        select(func.count(AdminSecurityEventFilterState.token_hash)).where(
            AdminSecurityEventFilterState.admin_user_id == admin.id
        )
    )
    assert admin_count == _MAX_ACTIVE_STATES_PER_ADMIN
    assert load_filter_state(other_token, other_admin.id) is not None


def test_clear_cookie_matches_security_attributes(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-B01-03: cookie deletion must match HttpOnly, SameSite=Lax, and Secure flags."""
    admin = _admin(make_user, email="cookie-attr-admin@example.com")
    _login(client, csrf_token, admin.email)
    assert _apply(client, csrf_token, identifier_hash=SENSITIVE_HASH).status_code == 303

    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", True)
    response = client.post(
        "/admin/security-events/filters/clear",
        data={"csrf_token": _form_token(client, csrf_token)},
    )
    assert response.status_code == 303
    set_cookie_headers = response.headers.getlist("Set-Cookie")
    matching = [h for h in set_cookie_headers if h.startswith(f"{FILTER_STATE_COOKIE}=")]
    assert len(matching) == 1
    header = matching[0]
    assert "HttpOnly" in header
    assert "SameSite=Lax" in header
    assert "Secure" in header
    assert "Path=/admin/security-events" in header


# ---------------------------------------------------------------------------
# Authorization, CSRF, and headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_non_admin_cannot_apply_filters(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    role: str,
) -> None:
    non_admin = make_user(email=f"filter-{role}@example.com", role=role)
    _login(client, csrf_token, non_admin.email)
    response = client.post(
        "/admin/security-events/filters",
        data={
            "csrf_token": csrf_token("/auth/account"),
            "identifier_hash": SENSITIVE_HASH,
        },
    )
    assert response.status_code == 403
    assert db.session.scalar(select(func.count(AdminSecurityEventFilterState.token_hash))) == 0


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
