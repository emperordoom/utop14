"""Integration tests for the admin security-event list."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select, text
from sqlalchemy import inspect as sa_inspect

from app.extensions import db
from app.models import AuditLog, SecurityEvent, User
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGIN_THROTTLED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
)
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.security_event_admin import (
    AdminSecurityEventFilters,
    list_security_events,
)

PASSWORD = "ValidPass123"


def _admin(make_user: Callable[..., User]) -> User:
    return make_user(
        email="security-events-admin@example.com",
        full_name="Security Events Admin",
        role=ROLE_ADMIN,
    )


def _silent_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
    *,
    email: str,
) -> None:
    """Authenticate without writing a login security event."""
    monkeypatch.setattr("app.auth.routes.record_login_succeeded", lambda **_kwargs: None)
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 302


def _login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    *,
    email: str,
) -> None:
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 302


def _logout(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": csrf_token("/auth/account")},
    )
    assert response.status_code == 302


def _add_event(
    *,
    event_type: str = SECURITY_EVENT_LOGOUT,
    outcome: str = SECURITY_OUTCOME_SUCCESS,
    reason_code: str = SECURITY_REASON_USER_REQUESTED,
    actor_user_id: int | None = None,
    actor_email: str | None = None,
    subject_user_id: int | None = None,
    subject_email: str | None = None,
    identifier_hash: str | None = None,
    ip_address: str = "127.0.0.1",
    user_agent: str = "pytest",
    request_id: str | None = None,
    metadata: dict | None = None,
    created_at: datetime | None = None,
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=event_type,
        outcome=outcome,
        reason_code=reason_code,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        subject_user_id=subject_user_id,
        subject_email=subject_email,
        identifier_hash=identifier_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        metadata_json=metadata or {},
    )
    if created_at is not None:
        event.created_at = created_at
    db.session.add(event)
    db.session.commit()
    return event


def _count_events() -> int:
    return db.session.scalar(select(func.count(SecurityEvent.id))) or 0


def _html(response) -> str:
    assert response.status_code == 200
    return response.get_data(as_text=True)


def _post_filters(client: FlaskClient, csrf_token: Callable[[str], str], **filters):
    """Submit filters through the POST endpoint (never through the URL)."""
    data: dict[str, object] = {"csrf_token": csrf_token("/admin/security-events")}
    data.update(filters)
    return client.post("/admin/security-events/filters", data=data)


def _apply_filters(client: FlaskClient, csrf_token: Callable[[str], str], **filters) -> None:
    response = _post_filters(client, csrf_token, **filters)
    assert response.status_code == 303, response.status_code


def _filtered(client: FlaskClient, csrf_token: Callable[[str], str], **filters) -> str:
    _apply_filters(client, csrf_token, **filters)
    return _html(client.get("/admin/security-events"))


def _invalid_filters(client: FlaskClient, csrf_token: Callable[[str], str], **filters) -> str:
    """Submit invalid filters and return the 200 validation page."""
    return _html(_post_filters(client, csrf_token, **filters))


@contextmanager
def _captured_sql():
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    sqlalchemy_event.listen(db.engine, "before_cursor_execute", _capture)
    try:
        yield statements
    finally:
        sqlalchemy_event.remove(db.engine, "before_cursor_execute", _capture)


def _table_body(html: str) -> str:
    return html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]


def test_admin_can_view_security_event_list(
    app: Flask,
    client: FlaskClient,
    make_user: Callable[..., User],
    login: Callable[..., object],
) -> None:
    admin = _admin(make_user)
    _add_event(event_type=SECURITY_EVENT_LOGOUT)
    login(admin.email)

    response = client.get("/admin/security-events")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Authentication" in html
    assert "Security events" in html
    assert "Recent" in html


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_non_admin_cannot_view_security_event_list(
    app: Flask,
    client: FlaskClient,
    make_user: Callable[..., User],
    login: Callable[..., object],
    role: str,
) -> None:
    actor = make_user(email=f"security-events-{role}@example.com", role=role)
    login(actor.email)

    response = client.get("/admin/security-events")

    assert response.status_code == 403


def test_anonymous_user_is_redirected_to_login(
    client: FlaskClient,
) -> None:
    response = client.get("/admin/security-events")

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_admin_navigation_and_dashboard_link_are_admin_only(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    login: Callable[..., object],
) -> None:
    admin = _admin(make_user)
    login(admin.email)
    admin_html = _html(client.get("/admin"))
    assert 'href="/admin/security-events"' in admin_html
    assert "Security events" in admin_html

    operator = make_user(email="security-events-operator-nav@example.com", role=ROLE_OPERATOR)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=operator.email)
    operator_html = client.get("/ops").get_data(as_text=True)
    assert "/admin/security-events" not in operator_html

    customer = make_user(email="security-events-customer-nav@example.com", role=ROLE_CUSTOMER)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=customer.email)
    customer_html = client.get("/auth/account").get_data(as_text=True)
    assert "/admin/security-events" not in customer_html


def test_list_renders_expected_fields(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    request_id = "a" * 32
    event = _add_event(
        event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        actor_user_id=admin.id,
        actor_email=admin.email,
        subject_user_id=admin.id,
        subject_email=admin.email,
        ip_address="203.0.113.10",
        request_id=request_id,
        metadata={"auth_method": "password", "remember_requested": True},
        user_agent="pytest-agent",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert f"#{event.id}" in html
    assert admin.email in html
    assert "203.0.113.10" in html
    assert "Login succeeded" in html
    assert "Success" in html
    assert "Authenticated" in html
    assert request_id[:12] in html
    assert request_id in html  # title/aria-label retains the full ID
    assert event.user_agent not in html
    assert "auth_method" not in html
    assert "remember_requested" not in html
    assert PASSWORD not in html
    assert admin.password_hash not in html


def test_list_preserves_deleted_identity_snapshots(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        event_type=SECURITY_EVENT_LOGOUT,
        actor_user_id=None,
        actor_email="deleted-actor@example.com",
        subject_user_id=None,
        subject_email="deleted-subject@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert f"#{event.id}" in html
    assert "deleted-actor@example.com" in html
    assert "deleted-subject@example.com" in html
    assert "#deleted" in html


def test_list_is_newest_first(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    older = _add_event(
        subject_user_id=admin.id,
        subject_email="older-event@example.com",
        created_at=now - timedelta(hours=2),
    )
    newer = _add_event(
        subject_user_id=admin.id,
        subject_email="newer-event@example.com",
        created_at=now,
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert html.index(newer.subject_email) < html.index(older.subject_email)
    assert f"#{newer.id}" in html


def test_equal_timestamps_order_by_id_descending(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    timestamp = datetime.now(UTC)
    first = _add_event(
        subject_user_id=admin.id,
        subject_email="first-equal@example.com",
        created_at=timestamp,
    )
    second = _add_event(
        subject_user_id=admin.id,
        subject_email="second-equal@example.com",
        created_at=timestamp,
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert second.id > first.id
    assert html.index(second.subject_email) < html.index(first.subject_email)


def test_list_paginates_twenty_per_page(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    for index in range(21):
        _add_event(
            subject_user_id=admin.id,
            subject_email=f"page-target-{index}@example.com",
            created_at=now - timedelta(minutes=index),
        )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    first = _html(client.get("/admin/security-events"))
    second = _html(client.get("/admin/security-events?page=2"))

    assert first.count('class="security-event-row"') == 20
    assert second.count('class="security-event-row"') == 1
    assert 'aria-label="Pagination"' in first
    assert "page-target-20@example.com" in second


def test_per_page_query_parameter_is_not_honoured(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    for index in range(21):
        _add_event(
            subject_user_id=admin.id,
            subject_email=f"fixed-page-{index}@example.com",
            created_at=now - timedelta(minutes=index),
        )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events?per_page=100"))

    assert html.count('class="security-event-row"') == 20


def test_empty_state_renders_when_no_events_exist(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert "No authentication events" in html
    assert "Nothing on the" in html


@pytest.mark.parametrize(
    "query",
    ["?page=999", "?page=1001", "?page=abc", "?page=0", "?page=-5"],
)
def test_invalid_or_out_of_range_page_is_safe(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
    query: str,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        subject_user_id=admin.id,
        subject_email="page-safety@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    response = client.get(f"/admin/security-events{query}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    if query in {"?page=999", "?page=1001"}:
        assert "No authentication events" in html
    else:
        assert f"#{event.id}" in html


def test_viewer_is_read_only_and_count_is_unchanged(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        subject_user_id=admin.id,
        subject_email="read-only@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)
    before = _count_events()

    assert client.get("/admin/security-events").status_code == 200
    assert client.get("/admin/security-events?page=2").status_code == 200

    assert _count_events() == before
    assert event.id in {item.id for item in db.session.scalars(select(SecurityEvent)).all()}


def test_mutation_methods_do_not_change_events(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(subject_user_id=admin.id, subject_email="mutation-safe@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)
    before = _count_events()

    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)("/admin/security-events")
        assert response.status_code == 405

    assert _count_events() == before


def test_list_does_not_render_private_event_fields(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    unknown_event = _add_event(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        identifier_hash="b" * 64,
        user_agent="SECRET-UA-TOKEN",
        metadata={"password": "SECRET-METADATA-PASSWORD", "token": "SECRET-METADATA-TOKEN"},
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert f"#{unknown_event.id}" in html
    assert "Unknown account" in html
    assert "b" * 64 not in html
    assert "SECRET-UA-TOKEN" not in html
    assert "SECRET-METADATA-PASSWORD" not in html
    assert "SECRET-METADATA-TOKEN" not in html
    assert "auth_method" not in html


def test_displayed_email_values_are_escaped(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    payload = "<script>alert(1)</script>"
    _add_event(
        actor_email=payload,
        subject_email="subject-escape@example.com",
        subject_user_id=admin.id,
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert payload not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_list_does_not_read_or_write_m13_audit_logs(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(subject_user_id=admin.id, subject_email="m13-safe@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)
    before = db.session.scalar(select(func.count(AuditLog.id))) or 0

    assert client.get("/admin/security-events").status_code == 200

    after = db.session.scalar(select(func.count(AuditLog.id))) or 0
    assert after == before == 0


def test_list_service_loads_only_list_columns(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _add_event(
        subject_user_id=admin.id,
        subject_email="load-only@example.com",
        identifier_hash="c" * 64,
        user_agent="load-only-agent",
        metadata={"auth_method": "password"},
    )
    db.session.remove()

    pagination = list_security_events(page=1)
    event = pagination.items[0]
    unloaded = sa_inspect(event).unloaded

    assert "metadata_json" in unloaded
    assert "user_agent" in unloaded
    assert "identifier_hash" in unloaded


def test_list_query_uses_only_security_events(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    admin = _admin(make_user)
    _add_event(subject_user_id=admin.id, subject_email="query-shape@example.com")
    db.session.remove()

    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    sqlalchemy_event.listen(db.engine, "before_cursor_execute", _capture)
    try:
        pagination = list_security_events(page=1)
    finally:
        sqlalchemy_event.remove(db.engine, "before_cursor_execute", _capture)

    assert pagination.items
    assert statements
    assert all("security_events" in statement for statement in statements)
    assert not any("audit_logs" in statement for statement in statements)
    assert not any("from users" in statement for statement in statements)


def test_filter_by_event_type(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(
        event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        actor_email="type-success@example.com",
    )
    _add_event(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        actor_email="type-failure@example.com",
    )
    _add_event(event_type=SECURITY_EVENT_LOGOUT, actor_email="type-logout@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(client, csrf_token, event_type="auth.login_failed")

    assert "type-failure@example.com" in html
    assert "type-success@example.com" not in html
    assert "type-logout@example.com" not in html


def test_filter_by_outcome(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="outcome-success@example.com")
    _add_event(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        actor_email="outcome-failure@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(client, csrf_token, outcome="failure")

    assert "outcome-failure@example.com" in html
    assert "outcome-success@example.com" not in html


def test_reason_filter_derives_event_type(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        actor_email="reason-unknown@example.com",
    )
    _add_event(actor_email="reason-success@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(client, csrf_token, reason="unknown_account")

    assert "reason-unknown@example.com" in html
    assert "reason-success@example.com" not in html


def test_filter_by_inclusive_utc_date_range(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(
        actor_email="date-before@example.com",
        created_at=datetime(2026, 11, 1, 23, 59, 59, tzinfo=UTC),
    )
    _add_event(
        actor_email="date-start@example.com",
        created_at=datetime(2026, 11, 2, 0, 0, 0, tzinfo=UTC),
    )
    _add_event(
        actor_email="date-end@example.com",
        created_at=datetime(2026, 11, 2, 23, 59, 59, 999999, tzinfo=UTC),
    )
    _add_event(
        actor_email="date-after@example.com",
        created_at=datetime(2026, 11, 3, 0, 0, 0, tzinfo=UTC),
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(
        client,
        csrf_token,
        date_from="2026-11-02",
        date_to="2026-11-02",
    )

    assert "date-start@example.com" in html
    assert "date-end@example.com" in html
    assert "date-before@example.com" not in html
    assert "date-after@example.com" not in html


def test_filter_by_maximum_date(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(
        actor_email="max-date@example.com",
        created_at=datetime(9999, 12, 31, 12, 0, tzinfo=UTC),
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(
        client,
        csrf_token,
        date_from="9999-12-31",
        date_to="9999-12-31",
    )

    assert "max-date@example.com" in html


def test_filter_by_request_id_exact(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    request_id = "c" * 32
    _add_event(actor_email="request-match@example.com", request_id=request_id)
    _add_event(actor_email="request-other@example.com", request_id="d" * 32)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(client, csrf_token, request_id=request_id)

    assert "request-match@example.com" in html
    assert "request-other@example.com" not in html

    invalid = _invalid_filters(client, csrf_token, request_id="not-a-request")
    assert "Request ID" in invalid
    assert "No results" in invalid


def test_filter_by_identifier_hash_hides_hash_from_rows(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    identifier_hash = "e" * 64
    _add_event(actor_email="hash-match@example.com", identifier_hash=identifier_hash)
    _add_event(actor_email="hash-other@example.com", identifier_hash="f" * 64)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _filtered(client, csrf_token, identifier_hash=identifier_hash)

    assert "hash-match@example.com" in html
    assert "hash-other@example.com" not in html
    assert identifier_hash not in _table_body(html)

    invalid = _invalid_filters(client, csrf_token, identifier_hash="E" * 64)
    assert "Identifier hash" in invalid
    assert "hash-match@example.com" not in invalid


def test_filter_by_actor_and_subject_user_ids(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    other = make_user(email="filter-other-user@example.com")
    _add_event(
        actor_user_id=admin.id,
        actor_email="actor-match@example.com",
        subject_user_id=other.id,
        subject_email="subject-match@example.com",
    )
    _add_event(
        actor_user_id=other.id,
        actor_email="actor-other@example.com",
        subject_user_id=admin.id,
        subject_email="subject-other@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    actor_html = _filtered(client, csrf_token, actor_user_id=str(admin.id))
    assert "actor-match@example.com" in actor_html
    assert "actor-other@example.com" not in actor_html

    subject_html = _filtered(client, csrf_token, subject_user_id=str(other.id))
    assert "subject-match@example.com" in subject_html
    assert "subject-other@example.com" not in subject_html

    invalid = _invalid_filters(client, csrf_token, actor_user_id="0")
    assert "Actor user ID" in invalid
    assert "actor-match@example.com" not in invalid


def test_invalid_filter_does_not_drop_valid_filter_or_show_results(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="invalid-filter-marker@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _invalid_filters(client, csrf_token, event_type="auth.logout", actor_user_id="0")

    assert "Actor user ID" in html
    assert 'value="auth.logout" selected' in html
    assert "invalid-filter-marker@example.com" not in html
    assert "Filters not applied" in html
    assert 'aria-label="Pagination"' not in html


def test_incompatible_reason_and_event_type_fails_closed(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="conflict-marker@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _invalid_filters(
        client,
        csrf_token,
        event_type="auth.login_succeeded",
        reason="user_requested",
    )

    assert "not compatible" in html
    assert "conflict-marker@example.com" not in html
    assert "No results" in html


def test_invalid_dates_fail_closed(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="invalid-date-marker@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    invalid_date = _invalid_filters(client, csrf_token, date_from="not-a-date")
    assert "From date" in invalid_date
    assert "invalid-date-marker@example.com" not in invalid_date

    reversed_range = _invalid_filters(
        client,
        csrf_token,
        date_from="2026-11-03",
        date_to="2026-11-01",
    )
    assert "on or before" in reversed_range
    assert "invalid-date-marker@example.com" not in reversed_range


def test_filter_preservation_across_pages(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    for index in range(21):
        _add_event(
            actor_email=f"filter-page-{index}@example.com",
            created_at=now - timedelta(minutes=index),
        )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    first = _filtered(
        client,
        csrf_token,
        event_type="auth.logout",
        outcome="success",
    )
    assert "page=2" in first
    assert "event_type=auth.logout" not in first
    assert "outcome=success" not in first

    second = _html(client.get("/admin/security-events?page=2"))
    assert "filter-page-20@example.com" in second
    assert "filter-page-0@example.com" not in second


def test_invalid_filter_does_not_render_pagination(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    now = datetime.now(UTC)
    for index in range(21):
        _add_event(
            actor_email=f"invalid-page-{index}@example.com",
            created_at=now - timedelta(minutes=index),
        )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _invalid_filters(client, csrf_token, event_type="invalid")

    assert "Select a valid event type." in html
    assert "invalid-page-0@example.com" not in html
    assert 'aria-label="Pagination"' not in html
    assert "page=2" not in html


def test_cache_control_is_private_no_store(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="cache-marker@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    for path in (
        "/admin/security-events",
        "/admin/security-events?page=999",
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "private, no-store"

    legacy = client.get("/admin/security-events?event_type=invalid")
    assert legacy.status_code == 303
    assert legacy.headers["Cache-Control"] == "private, no-store"
    assert "event_type" not in legacy.headers["Location"]


def test_admin_route_sql_shape_and_authorization_order(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    _add_event(actor_email="sql-shape@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    with _captured_sql() as statements:
        response = client.get("/admin/security-events")

    assert response.status_code == 200
    security_selects = [
        statement
        for statement in statements
        if statement.lstrip().startswith("select") and "security_events" in statement
    ]
    user_selects = [statement for statement in statements if "from users" in statement]
    writes = [
        statement
        for statement in statements
        if statement.lstrip().startswith(("insert", "update", "delete"))
    ]

    assert len(security_selects) == 2  # count + page select
    assert len(user_selects) == 1  # Flask-Login authentication lookup
    assert not any("audit_logs" in statement for statement in statements)
    assert writes == []

    operator = make_user(email="sql-shape-operator@example.com", role=ROLE_OPERATOR)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=operator.email)
    with _captured_sql() as statements:
        response = client.get("/admin/security-events")
    assert response.status_code == 403
    assert not any("security_events" in statement for statement in statements)
    assert not any("audit_logs" in statement for statement in statements)
    assert not any(
        statement.lstrip().startswith(("insert", "update", "delete")) for statement in statements
    )

    customer = make_user(email="sql-shape-customer@example.com", role=ROLE_CUSTOMER)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=customer.email)
    with _captured_sql() as statements:
        response = client.get("/admin/security-events")
    assert response.status_code == 403
    assert not any("security_events" in statement for statement in statements)

    _logout(client, csrf_token)
    with _captured_sql() as statements:
        response = client.get("/admin/security-events")
    assert response.status_code == 302
    assert not any("security_events" in statement for statement in statements)


def test_service_invalid_filter_object_fails_closed(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    _add_event(actor_email="service-invalid-marker@example.com")
    filters = AdminSecurityEventFilters(event_type="auth.not_real")

    pagination = list_security_events(filters)

    assert not filters.is_valid
    assert pagination.items == []


@pytest.mark.parametrize(
    ("query", "visible"),
    [
        ("?page=", True),
        ("?page=abc", True),
        ("?page=0", True),
        ("?page=-5", True),
        ("?page=+2", False),
        ("?page=002", False),
        ("?page=%202%20", False),
        ("?page=1&page=2", True),
        ("?page=9", False),
        ("?page=" + "9" * 5000, True),
        ("?page=%D9%A1%D9%A2", False),
        ("?page=1000", False),
        ("?page=1001", False),
        ("?per_page=1", True),
        ("?per_page=1000000", True),
    ],
)
def test_pagination_input_edge_cases(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
    query: str,
    visible: bool,
) -> None:
    admin = _admin(make_user)
    event = _add_event(actor_email="page-edge-marker@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    response = client.get(f"/admin/security-events{query}")
    html = _html(response)

    assert response.status_code == 200
    if visible:
        assert f"#{event.id}" in html
    else:
        assert f"#{event.id}" not in html


def test_request_id_attribute_context_is_escaped(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    payload = '"><script>alert(1)</script>'
    _add_event(actor_email="request-xss@example.com", request_id=payload)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get("/admin/security-events"))

    assert payload not in html
    assert "&lt;script&gt;" in html


def test_very_long_email_snapshot_is_safe(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    long_email = "a" * 240 + "@example.com"
    _add_event(actor_email=long_email)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    response = client.get("/admin/security-events")

    assert response.status_code == 200
    assert long_email in response.get_data(as_text=True)


def test_admin_can_view_security_event_detail(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    identifier_hash = "a" * 64
    request_id = "b" * 32
    event = _add_event(
        event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        actor_user_id=admin.id,
        actor_email=admin.email,
        subject_user_id=admin.id,
        subject_email=admin.email,
        identifier_hash=identifier_hash,
        ip_address="203.0.113.20",
        user_agent="Test Agent/1.0",
        request_id=request_id,
        metadata={
            "auth_method": "password",
            "remember_requested": True,
            "password": "SECRET-METADATA",
        },
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    response = client.get(f"/admin/security-events/{event.id}")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert f"#{event.id}" in html
    assert event.created_at.astimezone(UTC).strftime("%d %b %Y, %H:%M:%S UTC") in html
    assert "Login succeeded" in html
    assert "Success" in html
    assert "Authenticated" in html
    assert admin.email in html
    assert f"User #{admin.id}" in html
    assert "203.0.113.20" in html
    assert request_id in html
    assert "Test Agent/1.0" in html
    assert identifier_hash in html
    assert "HMAC-SHA256" in html
    assert "pseudonymous" in html
    assert "Authentication method" in html
    assert "Password" in html
    assert "Remember requested" in html
    assert "Yes" in html
    assert "SECRET-METADATA" not in html
    assert "SECURITY_EVENT_HASH_KEY" not in html

    list_html = _html(client.get("/admin/security-events"))
    assert f'href="/admin/security-events/{event.id}"' in list_html
    assert identifier_hash not in _table_body(list_html)

    related = html.split('class="security-event-related"', 1)[1].split("</article>", 1)[0]
    assert admin.email not in related
    assert 'action="/admin/security-events/filters"' in related
    assert 'name="request_id"' in related
    assert 'name="identifier_hash"' in related
    assert 'name="actor_user_id"' in related
    assert 'name="subject_user_id"' in related
    assert "?request_id=" not in related
    assert "?identifier_hash=" not in related


def test_detail_minimal_states(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        event_type=SECURITY_EVENT_LOGOUT,
        actor_user_id=None,
        actor_email=None,
        subject_user_id=None,
        subject_email=None,
        identifier_hash=None,
        user_agent="",
        metadata={},
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))

    assert html.count("Not identified") == 2
    assert "Not recorded." in html
    assert "Not provided" in html
    assert "No additional metadata recorded." in html
    assert "No related-event filters are available" in html


def test_detail_unknown_account(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    identifier_hash = "c" * 64
    event = _add_event(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        identifier_hash=identifier_hash,
        metadata={"auth_method": "password"},
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))

    assert "Unknown account" in html
    assert "No subject snapshot is stored" in html
    assert identifier_hash in html
    assert "Unknown account" in html
    assert "unknown-account" not in html.lower()


def test_detail_deleted_identity_snapshots(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        actor_user_id=None,
        actor_email="deleted-actor@example.com",
        subject_user_id=None,
        subject_email="deleted-subject@example.com",
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))

    assert "deleted-actor@example.com" in html
    assert "deleted-subject@example.com" in html
    assert html.count("Account link deleted") == 2


def test_detail_metadata_allowlist_and_empty_state(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    success = _add_event(
        event_type=SECURITY_EVENT_LOGIN_SUCCEEDED,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        metadata={
            "auth_method": "password",
            "remember_requested": "yes",
            "password": "SECRET",
            "nested": {"secret": "value"},
        },
    )
    logout = _add_event(event_type=SECURITY_EVENT_LOGOUT, metadata={"auth_method": "password"})
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    success_html = _html(client.get(f"/admin/security-events/{success.id}"))
    assert "Authentication method" in success_html
    assert "Password" in success_html
    assert "Remember requested" not in success_html
    assert "SECRET" not in success_html
    assert "nested" not in success_html

    logout_html = _html(client.get(f"/admin/security-events/{logout.id}"))
    assert "No additional metadata recorded." in logout_html


def test_detail_authorization_and_idor_boundary(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event_id = _add_event(actor_email="detail-idor@example.com").id
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    assert client.get(f"/admin/security-events/{event_id}").status_code == 200
    assert client.get("/admin/security-events/999999").status_code == 404
    assert client.get("/admin/security-events/not-an-int").status_code == 404

    customer = make_user(email="detail-customer@example.com", role=ROLE_CUSTOMER)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=customer.email)
    with _captured_sql() as statements:
        customer_existing = client.get(f"/admin/security-events/{event_id}")
    customer_missing = client.get("/admin/security-events/999999")
    assert customer_existing.status_code == 403
    assert customer_missing.status_code == 403
    assert not any("security_events" in statement for statement in statements)
    assert "detail-idor@example.com" not in customer_existing.get_data(as_text=True)

    operator = make_user(email="detail-operator@example.com", role=ROLE_OPERATOR)
    _logout(client, csrf_token)
    _login(client, csrf_token, email=operator.email)
    with _captured_sql() as statements:
        operator_existing = client.get(f"/admin/security-events/{event_id}")
    operator_missing = client.get("/admin/security-events/999999")
    assert operator_existing.status_code == 403
    assert operator_missing.status_code == 403
    assert not any("security_events" in statement for statement in statements)

    _logout(client, csrf_token)
    with _captured_sql() as statements:
        anonymous_existing = client.get(f"/admin/security-events/{event_id}")
    anonymous_missing = client.get("/admin/security-events/999999")
    assert anonymous_existing.status_code == 302
    assert anonymous_missing.status_code == 302
    assert not any("security_events" in statement for statement in statements)


def test_detail_mutation_methods_and_export_are_absent(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(actor_email="detail-read-only@example.com")
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)
    before = _count_events()

    for method in ("post", "put", "patch", "delete"):
        response = getattr(client, method)(f"/admin/security-events/{event.id}")
        assert response.status_code == 405

    assert client.get(f"/admin/security-events/{event.id}/export").status_code == 404
    assert client.get(f"/admin/security-events/{event.id}/delete").status_code == 404
    assert _count_events() == before

    assert client.get(f"/admin/security-events/{event.id}").status_code == 200
    assert _count_events() == before


def test_detail_sql_shape_and_no_relationship_queries(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        actor_user_id=admin.id,
        actor_email=admin.email,
        subject_user_id=admin.id,
        subject_email=admin.email,
        identifier_hash="d" * 64,
        request_id="e" * 32,
        metadata={"auth_method": "password", "remember_requested": True},
    )
    event_id = event.id
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    with _captured_sql() as statements:
        response = client.get(f"/admin/security-events/{event_id}")

    assert response.status_code == 200
    security_selects = [
        statement
        for statement in statements
        if statement.lstrip().startswith("select") and "security_events" in statement
    ]
    user_selects = [statement for statement in statements if "from users" in statement]
    writes = [
        statement
        for statement in statements
        if statement.lstrip().startswith(("insert", "update", "delete"))
    ]

    assert len(security_selects) == 1
    assert len(user_selects) == 1
    assert not any(" join " in statement for statement in security_selects)
    assert not any("audit_logs" in statement for statement in statements)
    assert writes == []


def test_detail_xss_payloads_are_escaped(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    payload = '"><script>alert(1)</script>'
    event = _add_event(
        actor_email=payload,
        subject_email="<img src=x onerror=alert(1)>",
        user_agent="<script>alert(1)</script>",
        request_id=payload,
        metadata={"auth_method": payload},
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))

    assert payload not in html
    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "SECURITY_EVENT_HASH_KEY" not in html


def test_detail_long_user_agent_is_escaped_text(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    long_agent = "A" * 500 + "<b>"
    event = _add_event(actor_email="long-agent@example.com", user_agent=long_agent)
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))

    assert "A" * 500 in html
    assert "<b>" not in html
    assert "&lt;b&gt;" in html


def test_related_event_links_follow_and_fail_closed(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    request_id = "f" * 32
    identifier_hash = "a" * 64
    event = _add_event(
        actor_user_id=admin.id,
        actor_email="related-actor@example.com",
        subject_user_id=admin.id,
        subject_email="related-subject@example.com",
        request_id=request_id,
        identifier_hash=identifier_hash,
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    html = _html(client.get(f"/admin/security-events/{event.id}"))
    related = html.split('class="security-event-related"', 1)[1].split("</article>", 1)[0]
    assert "related-actor@example.com" not in related
    assert "related-subject@example.com" not in related
    assert 'action="/admin/security-events/filters"' in related
    assert 'name="request_id"' in related
    assert 'name="identifier_hash"' in related
    assert 'name="actor_user_id"' in related
    assert 'name="subject_user_id"' in related
    assert "?request_id=" not in related
    assert "?identifier_hash=" not in related

    request_list = _filtered(client, csrf_token, request_id=request_id)
    assert "related-actor@example.com" in request_list
    identifier_list = _filtered(client, csrf_token, identifier_hash=identifier_hash)
    assert "related-actor@example.com" in identifier_list

    malformed = _add_event(
        actor_email="malformed-related@example.com",
        request_id="bad",
    )
    malformed_html = _html(client.get(f"/admin/security-events/{malformed.id}"))
    assert "bad" in malformed_html
    assert 'name="request_id"' in malformed_html
    assert "?request_id=" not in malformed_html
    malformed_list = _invalid_filters(client, csrf_token, request_id="bad")
    assert "Request ID" in malformed_list
    assert "malformed-related@example.com" not in malformed_list


@pytest.mark.parametrize("timezone", ["UTC", "Asia/Jakarta"])
def test_security_event_timestamps_render_utc_for_database_timezone(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
    database_timezone: Callable[[str], None],
    timezone: str,
) -> None:
    database_timezone(timezone)
    assert db.session.execute(text("SHOW timezone")).scalar_one() == timezone

    admin = _admin(make_user)
    event = _add_event(created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))
    event_id = event.id
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    list_html = _html(client.get("/admin/security-events"))
    detail_html = _html(client.get(f"/admin/security-events/{event_id}"))

    assert "01 Jan 2026, 00:00:00 UTC" in list_html
    assert "01 Jan 2026, 00:00:00 UTC" in detail_html
    assert "01 Jan 2026, 07:00:00 UTC" not in list_html
    assert "01 Jan 2026, 07:00:00 UTC" not in detail_html


def test_login_throttled_event_renders_and_filters(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    event = _add_event(
        event_type=SECURITY_EVENT_LOGIN_THROTTLED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_IDENTIFIER_RATE_LIMITED,
        metadata={
            "scope": "identifier",
            "retry_after_seconds": 60,
            "window_seconds": 900,
            "failure_count": 5,
        },
    )
    _silent_login(client, csrf_token, monkeypatch, email=admin.email)

    list_html = _html(client.get("/admin/security-events"))
    assert "Login throttled" in list_html
    assert "Identifier rate limited" in list_html
    assert f"#{event.id}" in list_html

    reason_html = _filtered(client, csrf_token, reason="identifier_rate_limited")
    assert f"#{event.id}" in reason_html

    type_html = _filtered(client, csrf_token, event_type="auth.login_throttled")
    assert f"#{event.id}" in type_html

    detail_html = _html(client.get(f"/admin/security-events/{event.id}"))
    assert "Login throttled" in detail_html
    assert "Identifier rate limited" in detail_html
    assert "Rate-limit scope" in detail_html
    assert "Retry after (seconds)" in detail_html
    assert "Window (seconds)" in detail_html
    assert "Failure count" in detail_html
    assert "60" in detail_html
    assert "900" in detail_html
    assert "5" in detail_html
    assert "identifier_rate_limited" in detail_html
