"""Integration tests for M14.1 authentication security events."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.wrappers import Response

from app.extensions import db
from app.models import AuditLog, SecurityEvent, User
from app.models.security_event import (
    SECURITY_EVENT_LOGIN_FAILED,
    SECURITY_EVENT_LOGIN_SUCCEEDED,
    SECURITY_EVENT_LOGOUT,
    SECURITY_OUTCOME_FAILURE,
    SECURITY_OUTCOME_SUCCESS,
    SECURITY_REASON_AUTHENTICATED,
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
    SECURITY_REASON_USER_REQUESTED,
)
from app.models.user import ROLE_CUSTOMER

PASSWORD = "ValidPass123"


def _events() -> list[SecurityEvent]:
    return list(db.session.scalars(select(SecurityEvent).order_by(SecurityEvent.id)).all())


def _event_count() -> int:
    return db.session.scalar(select(func.count(SecurityEvent.id))) or 0


def _audit_count() -> int:
    return db.session.scalar(select(func.count(AuditLog.id))) or 0


def _login(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    email: str,
    password: str = PASSWORD,
    follow_redirects: bool = False,
    headers: dict[str, str] | None = None,
) -> Response:
    return client.post(
        "/auth/login",
        data={
            "csrf_token": token_for("/auth/login"),
            "email": email,
            "password": password,
        },
        follow_redirects=follow_redirects,
        headers=headers,
    )


def _register(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    email: str,
    password: str = PASSWORD,
    follow_redirects: bool = False,
) -> Response:
    return client.post(
        "/auth/register",
        data={
            "csrf_token": token_for("/auth/register"),
            "full_name": "Security Event User",
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=follow_redirects,
    )


def _add_event(user: User) -> SecurityEvent:
    event = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        actor_user_id=user.id,
        actor_email=user.email,
        subject_user_id=user.id,
        subject_email=user.email,
        ip_address="127.0.0.1",
        user_agent="pytest",
        request_id=None,
        metadata_json={},
    )
    db.session.add(event)
    db.session.commit()
    return event


def _csrf_for(client: FlaskClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def _create_user_in_app(
    application: Flask,
    email: str,
    *,
    is_active: bool = True,
) -> int:
    with application.app_context():
        user = User(
            email=email,
            full_name="Pool Test User",
            role=ROLE_CUSTOMER,
            is_active=is_active,
        )
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.flush()
        user_id = user.id
        assert user_id is not None
        db.session.commit()
        db.session.remove()
        return user_id


def _event_rows_for_app(application: Flask) -> list[dict[str, object]]:
    with application.app_context():
        rows = [
            {
                "event_type": event.event_type,
                "outcome": event.outcome,
                "reason_code": event.reason_code,
                "actor_user_id": event.actor_user_id,
                "actor_email": event.actor_email,
                "subject_user_id": event.subject_user_id,
                "subject_email": event.subject_email,
                "identifier_hash": event.identifier_hash,
                "ip_address": str(event.ip_address),
                "user_agent": event.user_agent,
                "request_id": event.request_id,
                "metadata": event.metadata_json,
            }
            for event in db.session.scalars(select(SecurityEvent).order_by(SecurityEvent.id))
        ]
        db.session.remove()
        return rows


def _checked_out(application: Flask) -> int:
    with application.app_context():
        return db.engine.pool.checkedout()


def test_login_success_records_exactly_one_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="success@example.com")

    response = _login(client, csrf_token, email="success@example.com")

    assert response.status_code == 302
    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == SECURITY_EVENT_LOGIN_SUCCEEDED
    assert event.outcome == SECURITY_OUTCOME_SUCCESS
    assert event.reason_code == SECURITY_REASON_AUTHENTICATED
    assert event.actor_user_id == user.id
    assert event.actor_email == user.email
    assert event.subject_user_id == user.id
    assert event.subject_email == user.email
    assert event.identifier_hash is None
    assert event.metadata_json == {
        "auth_method": "password",
        "remember_requested": False,
    }
    assert str(event.ip_address) == "127.0.0.1"
    assert event.request_id is not None
    assert len(event.request_id) == 32
    assert event.created_at.tzinfo is not None
    assert event.created_at <= datetime.now(UTC)


def test_registration_auto_login_records_exactly_one_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _register(client, csrf_token, email="new@example.com")

    assert response.status_code == 302
    user = db.session.scalar(select(User).where(User.email == "new@example.com"))
    assert user is not None

    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == SECURITY_EVENT_LOGIN_SUCCEEDED
    assert event.outcome == SECURITY_OUTCOME_SUCCESS
    assert event.reason_code == SECURITY_REASON_AUTHENTICATED
    assert event.actor_user_id == user.id
    assert event.subject_user_id == user.id
    assert event.metadata_json == {
        "auth_method": "registration",
        "remember_requested": False,
    }


def test_constrained_pool_login_success(
    constrained_pool_app: Flask,
) -> None:
    with constrained_pool_app.app_context():
        assert db.engine.pool.size() == 1

    _create_user_in_app(constrained_pool_app, "pool-success@example.com")
    client = constrained_pool_app.test_client()

    def token_for(path: str) -> str:
        return _csrf_for(client, path)

    response = _login(
        client,
        token_for,
        email="pool-success@example.com",
    )

    assert response.status_code == 302
    assert _checked_out(constrained_pool_app) == 0
    rows = _event_rows_for_app(constrained_pool_app)
    assert len(rows) == 1
    assert rows[0]["event_type"] == SECURITY_EVENT_LOGIN_SUCCEEDED
    assert _checked_out(constrained_pool_app) == 0


def test_constrained_pool_login_failures(
    constrained_pool_app: Flask,
) -> None:
    _create_user_in_app(constrained_pool_app, "pool-failure@example.com")
    client = constrained_pool_app.test_client()

    def token_for(path: str) -> str:
        return _csrf_for(client, path)

    wrong = _login(
        client,
        token_for,
        email="pool-failure@example.com",
        password="WrongPass123",
    )
    unknown = _login(client, token_for, email="pool-missing@example.com")

    assert wrong.status_code == 200
    assert unknown.status_code == 200
    assert _checked_out(constrained_pool_app) == 0
    rows = _event_rows_for_app(constrained_pool_app)
    assert len(rows) == 2
    assert [row["reason_code"] for row in rows] == [
        SECURITY_REASON_INVALID_PASSWORD,
        SECURITY_REASON_UNKNOWN_ACCOUNT,
    ]
    assert _checked_out(constrained_pool_app) == 0


def test_constrained_pool_logout(
    constrained_pool_app: Flask,
) -> None:
    _create_user_in_app(constrained_pool_app, "pool-logout@example.com")
    client = constrained_pool_app.test_client()

    def token_for(path: str) -> str:
        return _csrf_for(client, path)

    login_response = _login(client, token_for, email="pool-logout@example.com")
    assert login_response.status_code == 302
    logout_response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )

    assert logout_response.status_code == 302
    assert _checked_out(constrained_pool_app) == 0
    rows = _event_rows_for_app(constrained_pool_app)
    assert len(rows) == 2
    assert rows[1]["event_type"] == SECURITY_EVENT_LOGOUT
    assert _checked_out(constrained_pool_app) == 0


def test_constrained_pool_registration(
    constrained_pool_app: Flask,
) -> None:
    client = constrained_pool_app.test_client()

    def token_for(path: str) -> str:
        return _csrf_for(client, path)

    response = _register(client, token_for, email="pool-register@example.com")

    assert response.status_code == 302
    assert _checked_out(constrained_pool_app) == 0
    rows = _event_rows_for_app(constrained_pool_app)
    assert len(rows) == 1
    assert rows[0]["event_type"] == SECURITY_EVENT_LOGIN_SUCCEEDED
    assert rows[0]["metadata"] == {
        "auth_method": "registration",
        "remember_requested": False,
    }
    assert _checked_out(constrained_pool_app) == 0


def test_wrong_password_records_invalid_password_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="wrong@example.com")

    response = _login(
        client,
        csrf_token,
        email="wrong@example.com",
        password="WrongPass123",
    )

    assert response.status_code == 200
    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == SECURITY_EVENT_LOGIN_FAILED
    assert event.outcome == SECURITY_OUTCOME_FAILURE
    assert event.reason_code == SECURITY_REASON_INVALID_PASSWORD
    assert event.actor_user_id is None
    assert event.subject_user_id == user.id
    assert event.subject_email == user.email
    assert event.metadata_json == {"auth_method": "password"}


def test_unknown_account_records_unknown_event_without_raw_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _login(client, csrf_token, email="missing@example.com")

    assert response.status_code == 200
    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == SECURITY_EVENT_LOGIN_FAILED
    assert event.reason_code == SECURITY_REASON_UNKNOWN_ACCOUNT
    assert event.actor_user_id is None
    assert event.actor_email is None
    assert event.subject_user_id is None
    assert event.subject_email is None
    assert event.identifier_hash is not None
    assert len(event.identifier_hash) == 64
    assert "missing@example.com" not in event.identifier_hash
    assert "missing@example.com" not in str(event.metadata_json)


def test_inactive_account_records_inactive_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="inactive-event@example.com", is_active=False)

    response = _login(client, csrf_token, email="inactive-event@example.com")

    assert response.status_code == 200
    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.event_type == SECURITY_EVENT_LOGIN_FAILED
    assert event.reason_code == SECURITY_REASON_INACTIVE_ACCOUNT
    assert event.subject_user_id == user.id
    assert event.subject_email == user.email


def test_login_failure_responses_remain_generic(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="active@example.com")
    make_user(email="disabled@example.com", is_active=False)

    wrong = _login(client, csrf_token, email="active@example.com", password="WrongPass123")
    unknown = _login(client, csrf_token, email="nobody@example.com")
    inactive = _login(client, csrf_token, email="disabled@example.com")

    for response in (wrong, unknown, inactive):
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "Invalid email or password." in body
        for leaked in ("unknown_account", "inactive_account", "invalid_password"):
            assert leaked not in body
    assert _event_count() == 3


def test_invalid_form_does_not_record_login_failure(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _login(client, csrf_token, email="not-an-email")

    assert response.status_code == 200
    assert _event_count() == 0


def test_missing_csrf_does_not_record_login_failure(
    client: FlaskClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="csrf@example.com")

    response = client.post(
        "/auth/login",
        data={"email": "csrf@example.com", "password": PASSWORD},
    )

    assert response.status_code == 400
    assert _event_count() == 0


def test_dummy_verification_runs_for_unknown_account(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"dummy": 0, "real": 0}
    real_verify = User.verify_password

    def fake_real_verify(self, password):
        calls["real"] += 1
        return real_verify(self, password)

    def fake_dummy(password):
        calls["dummy"] += 1
        return False

    monkeypatch.setattr(User, "verify_password", fake_real_verify)
    monkeypatch.setattr("app.auth.routes.verify_dummy_password", fake_dummy)

    response = _login(client, csrf_token, email="missing@example.com")

    assert response.status_code == 200
    assert calls == {"dummy": 1, "real": 0}


def test_dummy_verification_runs_for_inactive_account(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="inactive-dummy@example.com", is_active=False)
    calls = {"dummy": 0, "real": 0}
    real_verify = User.verify_password

    def fake_real_verify(self, password):
        calls["real"] += 1
        return real_verify(self, password)

    def fake_dummy(password):
        calls["dummy"] += 1
        return False

    monkeypatch.setattr(User, "verify_password", fake_real_verify)
    monkeypatch.setattr("app.auth.routes.verify_dummy_password", fake_dummy)

    response = _login(client, csrf_token, email="inactive-dummy@example.com")

    assert response.status_code == 200
    assert calls == {"dummy": 1, "real": 0}


@pytest.mark.parametrize(
    ("email", "password", "expected_real", "expected_dummy"),
    [
        ("wrong-real@example.com", "WrongPass123", 1, 0),
        ("correct-real@example.com", PASSWORD, 1, 0),
    ],
)
def test_real_verification_runs_for_known_accounts(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
    email: str,
    password: str,
    expected_real: int,
    expected_dummy: int,
) -> None:
    make_user(email=email)
    calls = {"dummy": 0, "real": 0}
    real_verify = User.verify_password

    def fake_real_verify(self, candidate):
        calls["real"] += 1
        return real_verify(self, candidate)

    def fake_dummy(candidate):
        calls["dummy"] += 1
        return False

    monkeypatch.setattr(User, "verify_password", fake_real_verify)
    monkeypatch.setattr("app.auth.routes.verify_dummy_password", fake_dummy)

    _login(client, csrf_token, email=email, password=password)

    assert calls == {"real": expected_real, "dummy": expected_dummy}


def test_logout_records_exactly_one_logout_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="logout@example.com")
    _login(client, csrf_token, email="logout@example.com")

    response = client.post("/auth/logout", data={"csrf_token": csrf_token("/auth/account")})

    assert response.status_code == 302
    events = _events()
    assert len(events) == 2
    assert events[0].event_type == SECURITY_EVENT_LOGIN_SUCCEEDED
    logout_event = events[1]
    assert logout_event.event_type == SECURITY_EVENT_LOGOUT
    assert logout_event.outcome == SECURITY_OUTCOME_SUCCESS
    assert logout_event.reason_code == SECURITY_REASON_USER_REQUESTED
    assert logout_event.actor_user_id == user.id
    assert logout_event.actor_email == user.email
    assert logout_event.subject_user_id == user.id
    assert logout_event.subject_email == user.email
    assert logout_event.metadata_json == {}
    assert logout_event.request_id is not None


def test_login_success_records_remember_requested_true(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="remember-event@example.com")

    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": "remember-event@example.com",
            "password": PASSWORD,
            "remember": "y",
        },
    )

    assert response.status_code == 302
    event = _events()[0]
    assert event.metadata_json == {
        "auth_method": "password",
        "remember_requested": True,
    }


def test_logout_csrf_failure_records_no_logout_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="logout-csrf@example.com")
    _login(client, csrf_token, email="logout-csrf@example.com")
    assert _event_count() == 1

    response = client.post("/auth/logout", data={})

    assert response.status_code == 400
    assert _event_count() == 1


def test_unauthenticated_logout_records_no_logout_event(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    token = csrf_token("/auth/login")

    response = client.post("/auth/logout", data={"csrf_token": token})

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")
    assert _event_count() == 0


def test_auth_events_do_not_write_to_m13_audit_logs(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="m13-untouched@example.com")
    _login(client, csrf_token, email="m13-untouched@example.com")
    client.post("/auth/logout", data={"csrf_token": csrf_token("/auth/account")})

    assert _event_count() == 2
    assert _audit_count() == 0


def test_events_never_contain_credentials_or_session_secrets(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="sensitive@example.com")
    _login(client, csrf_token, email="sensitive@example.com", password="WrongPass123")
    _login(client, csrf_token, email="sensitive@example.com")

    events = _events()
    assert len(events) == 2
    for event in events:
        serialized = " ".join(
            str(value)
            for value in (
                event.event_type,
                event.outcome,
                event.reason_code,
                event.actor_email,
                event.subject_email,
                event.identifier_hash,
                event.user_agent,
                event.metadata_json,
            )
        )
        assert PASSWORD not in serialized
        assert user.password_hash not in serialized
        for key in event.metadata_json:
            lowered = key.lower()
            assert "password" not in lowered
            assert "token" not in lowered
            assert "session" not in lowered
            assert "csrf" not in lowered


def test_event_data_excludes_session_remember_csrf_and_password_secrets(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="secret-values@example.com")
    password_hash = user.password_hash
    token = csrf_token("/auth/login")

    response = client.post(
        "/auth/login",
        data={
            "csrf_token": token,
            "email": user.email,
            "password": PASSWORD,
            "remember": "y",
        },
    )

    assert response.status_code == 302
    session_cookie = client.get_cookie("utop14_session")
    remember_cookie = client.get_cookie("utop14_remember")
    assert session_cookie is not None
    assert remember_cookie is not None
    forbidden = (
        PASSWORD,
        password_hash,
        token,
        session_cookie.value,
        remember_cookie.value,
    )

    for event in _events():
        serialized = " ".join(
            str(value)
            for value in (
                event.event_type,
                event.outcome,
                event.reason_code,
                event.actor_email,
                event.subject_email,
                event.identifier_hash,
                event.ip_address,
                event.user_agent,
                event.request_id,
                event.metadata_json,
            )
        )
        for value in forbidden:
            assert value not in serialized


def test_missing_hash_key_does_not_store_raw_unknown_identifier(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "SECURITY_EVENT_HASH_KEY", "")

    response = _login(client, csrf_token, email="no-key@example.com")

    assert response.status_code == 200
    assert "Invalid email or password." in response.get_data(as_text=True)
    events = _events()
    assert len(events) == 1
    event = events[0]
    assert event.reason_code == SECURITY_REASON_UNKNOWN_ACCOUNT
    assert event.identifier_hash is None
    assert event.actor_email is None
    assert event.subject_email is None
    assert "no-key@example.com" not in str(event.metadata_json)


class _FailingSession:
    """Stand-in session whose commit fails, simulating audit storage outage."""

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self) -> _FailingSession:
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def add(self, _event: SecurityEvent) -> None:
        pass

    def commit(self) -> None:
        raise SQLAlchemyError("simulated security event persistence failure")


def test_persistence_failure_does_not_change_login_success(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="outage@example.com")
    monkeypatch.setattr("app.services.security_events.Session", _FailingSession)

    response = _login(client, csrf_token, email="outage@example.com", follow_redirects=True)

    assert response.status_code == 200
    assert "Signed in. Welcome back." in response.get_data(as_text=True)
    assert client.get("/auth/account").status_code == 200
    assert _event_count() == 0


def test_persistence_failure_does_not_change_login_failure(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="outage-failure@example.com")
    monkeypatch.setattr("app.services.security_events.Session", _FailingSession)

    response = _login(
        client,
        csrf_token,
        email="outage-failure@example.com",
        password="WrongPass123",
    )

    assert response.status_code == 200
    assert "Invalid email or password." in response.get_data(as_text=True)
    assert client.get("/auth/account").status_code == 302
    assert _event_count() == 0


def test_persistence_failure_does_not_change_logout(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="outage-logout@example.com")
    _login(client, csrf_token, email="outage-logout@example.com")
    token = csrf_token("/auth/account")
    monkeypatch.setattr("app.services.security_events.Session", _FailingSession)

    response = client.post("/auth/logout", data={"csrf_token": token})

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert client.get("/auth/account").status_code == 302


def test_persistence_failure_does_not_break_registration(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.services.security_events.Session", _FailingSession)

    response = _register(client, csrf_token, email="outage-registration@example.com")

    assert response.status_code == 302
    user = db.session.scalar(select(User).where(User.email == "outage-registration@example.com"))
    assert user is not None
    assert _event_count() == 0


def test_internal_exception_is_not_classified_as_login_failure(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="internal-error@example.com")

    def _raise_verification_error(_self, _password):
        raise RuntimeError("simulated password verification failure")

    monkeypatch.setattr(User, "verify_password", _raise_verification_error)
    monkeypatch.setitem(app.config, "PROPAGATE_EXCEPTIONS", False)

    response = _login(client, csrf_token, email="internal-error@example.com")

    assert response.status_code == 500
    assert _event_count() == 0


def test_persistence_failure_log_includes_request_id_without_identifiers(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "log-correlation@example.com"
    make_user(email=email)
    messages: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        app.logger,
        "error",
        lambda *args, **_kwargs: messages.append(args),
    )
    monkeypatch.setattr("app.services.security_events.Session", _FailingSession)

    response = _login(client, csrf_token, email=email)

    assert response.status_code == 302
    joined = " ".join(str(message) for message in messages)
    assert "request_id=" in joined
    assert re.search(r"[0-9a-f]{32}", joined)
    assert email not in joined
    assert PASSWORD not in joined


def test_security_event_update_is_rejected_by_database_trigger(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="trigger-update@example.com")
    event = _add_event(user)

    with pytest.raises(SQLAlchemyError):
        db.session.execute(
            update(SecurityEvent)
            .where(SecurityEvent.id == event.id)
            .values(reason_code=SECURITY_REASON_AUTHENTICATED)
        )
        db.session.commit()
    db.session.rollback()

    db.session.refresh(event)
    assert event.reason_code == SECURITY_REASON_USER_REQUESTED


def test_security_event_delete_is_rejected_by_database_trigger(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="trigger-delete@example.com")
    event = _add_event(user)

    with pytest.raises(SQLAlchemyError):
        db.session.execute(delete(SecurityEvent).where(SecurityEvent.id == event.id))
        db.session.commit()
    db.session.rollback()

    assert db.session.get(SecurityEvent, event.id) is not None


def test_historical_identity_survives_user_deletion(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="deleted-security-user@example.com")
    event = _add_event(user)
    event_id = event.id

    db.session.delete(user)
    db.session.commit()

    persisted = db.session.get(SecurityEvent, event_id)
    assert persisted is not None
    assert persisted.actor_user_id is None
    assert persisted.subject_user_id is None
    assert persisted.actor_email == "deleted-security-user@example.com"
    assert persisted.subject_email == "deleted-security-user@example.com"


def test_fk_set_null_clears_only_the_deleted_identity(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    actor = make_user(email="actor-distinct@example.com")
    subject = make_user(email="subject-distinct@example.com")
    actor_id = actor.id
    subject_id = subject.id
    event = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        actor_user_id=actor_id,
        actor_email=actor.email,
        subject_user_id=subject_id,
        subject_email=subject.email,
        ip_address="127.0.0.1",
        user_agent="pytest",
        metadata_json={},
    )
    db.session.add(event)
    db.session.commit()
    event_id = event.id

    db.session.delete(actor)
    db.session.commit()
    db.session.expire_all()
    persisted = db.session.get(SecurityEvent, event_id)
    assert persisted is not None
    assert persisted.actor_user_id is None
    assert persisted.actor_email == "actor-distinct@example.com"
    assert persisted.subject_user_id == subject_id
    assert persisted.subject_email == "subject-distinct@example.com"

    db.session.delete(subject)
    db.session.commit()
    db.session.expire_all()
    persisted = db.session.get(SecurityEvent, event_id)
    assert persisted is not None
    assert persisted.subject_user_id is None
    assert persisted.subject_email == "subject-distinct@example.com"


def test_append_only_trigger_permits_direct_identity_clearing(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    """Ordinary UPDATE/DELETE is rejected, but clearing either nullable FK to
    NULL is permitted (FK SET NULL or direct privileged UPDATE); other fields
    remain immutable."""
    user = make_user(email="direct-clear@example.com")
    event = _add_event(user)
    event_id = event.id

    db.session.execute(
        update(SecurityEvent)
        .where(SecurityEvent.id == event_id)
        .values(actor_user_id=None, subject_user_id=None)
    )
    db.session.commit()
    db.session.expire_all()

    persisted = db.session.get(SecurityEvent, event_id)
    assert persisted is not None
    assert persisted.actor_user_id is None
    assert persisted.subject_user_id is None
    assert persisted.actor_email == "direct-clear@example.com"
    assert persisted.subject_email == "direct-clear@example.com"


def test_security_event_user_agent_is_truncated(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="ua-event@example.com")

    _login(
        client,
        csrf_token,
        email="ua-event@example.com",
        headers={"User-Agent": "A" * 600},
    )

    event = _events()[0]
    assert len(event.user_agent) == 512


def test_security_event_invalid_ip_uses_unknown_sentinel(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="ip-event@example.com")

    response = client.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "email": "ip-event@example.com",
            "password": PASSWORD,
        },
        environ_overrides={"REMOTE_ADDR": "not-an-ip"},
    )

    assert response.status_code == 302
    event = _events()[0]
    assert str(event.ip_address) == "0.0.0.0"


def test_security_event_database_constraints(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="constraint-security@example.com")

    invalid_type = SecurityEvent(
        event_type="auth.not_real",
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        actor_user_id=user.id,
        actor_email=user.email,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    db.session.add(invalid_type)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    invalid_reason = SecurityEvent(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_AUTHENTICATED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    db.session.add(invalid_reason)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    invalid_metadata = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome=SECURITY_OUTCOME_SUCCESS,
        reason_code=SECURITY_REASON_USER_REQUESTED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json=["not", "an", "object"],
    )
    db.session.add(invalid_metadata)
    with pytest.raises(SQLAlchemyError):
        db.session.commit()
    db.session.rollback()

    invalid_outcome = SecurityEvent(
        event_type=SECURITY_EVENT_LOGOUT,
        outcome="denied",
        reason_code=SECURITY_REASON_USER_REQUESTED,
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    db.session.add(invalid_outcome)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    invalid_hash = SecurityEvent(
        event_type=SECURITY_EVENT_LOGIN_FAILED,
        outcome=SECURITY_OUTCOME_FAILURE,
        reason_code=SECURITY_REASON_UNKNOWN_ACCOUNT,
        identifier_hash="not-a-64-character-digest",
        ip_address="127.0.0.1",
        user_agent="",
        metadata_json={},
    )
    db.session.add(invalid_hash)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()
