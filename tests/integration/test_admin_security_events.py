"""Integration tests for the admin security-event list."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select
from sqlalchemy import inspect as sa_inspect

from app.extensions import db
from app.models import AuditLog, SecurityEvent, User
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
)
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.security_event_admin import list_security_events

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
