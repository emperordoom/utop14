"""Integration tests for registration, login, logout and CSRF."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from flask.testing import FlaskClient
from sqlalchemy import func, select
from werkzeug.wrappers import Response

from app.extensions import db
from app.models import User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER

PASSWORD = "ValidPass123"


def _register(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    email: str,
    full_name: str = "Test User",
    password: str = PASSWORD,
    confirm_password: str | None = None,
    extra: dict[str, str] | None = None,
    follow_redirects: bool = False,
) -> Response:
    data = {
        "csrf_token": token_for("/auth/register"),
        "full_name": full_name,
        "email": email,
        "password": password,
        "confirm_password": password if confirm_password is None else confirm_password,
    }
    if extra:
        data.update(extra)
    return client.post("/auth/register", data=data, follow_redirects=follow_redirects)


def _login(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    email: str,
    password: str = PASSWORD,
    next_url: str | None = None,
    follow_redirects: bool = False,
) -> Response:
    data = {
        "csrf_token": token_for("/auth/login"),
        "email": email,
        "password": password,
    }
    if next_url is not None:
        data["next"] = next_url
    return client.post("/auth/login", data=data, follow_redirects=follow_redirects)


def test_registration_creates_customer_with_hashed_password(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _register(
        client,
        csrf_token,
        email="  New.User@Example.COM ",
        full_name="New User",
        follow_redirects=True,
    )

    assert response.status_code == 200
    user = db.session.scalar(select(User).where(User.email == "new.user@example.com"))
    assert user is not None
    assert user.role == ROLE_CUSTOMER
    assert user.full_name == "New User"
    assert user.password_hash != PASSWORD
    assert PASSWORD not in user.password_hash
    assert user.verify_password(PASSWORD) is True
    assert user.last_login_at is not None
    assert user.last_login_at.tzinfo is not None

    html = response.get_data(as_text=True)
    assert "Account details" in html
    assert "new.user@example.com" in html
    assert "password_hash" not in html
    assert PASSWORD not in html


def test_registration_rejects_duplicate_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="existing@example.com")

    response = _register(
        client,
        csrf_token,
        email=" EXISTING@example.com ",
    )

    assert response.status_code == 200
    assert "An account with that email already exists." in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count(User.id))) == 1


def test_registration_ignores_client_supplied_role(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _register(
        client,
        csrf_token,
        email="escalate@example.com",
        extra={"role": ROLE_ADMIN},
    )

    assert response.status_code == 302
    user = db.session.scalar(select(User).where(User.email == "escalate@example.com"))
    assert user is not None
    assert user.role == ROLE_CUSTOMER


def test_registration_rejects_invalid_email_and_short_password(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    response = _register(
        client,
        csrf_token,
        email="not-an-email",
        password="short",
        confirm_password="short",
    )

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(User.id))) == 0


def test_registration_requires_csrf(client: FlaskClient) -> None:
    response = client.post(
        "/auth/register",
        data={
            "full_name": "No Token",
            "email": "no-token@example.com",
            "password": PASSWORD,
            "confirm_password": PASSWORD,
        },
    )

    assert response.status_code == 400
    assert db.session.scalar(select(func.count(User.id))) == 0


def test_login_requires_csrf(
    client: FlaskClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")

    response = client.post(
        "/auth/login",
        data={"email": "user@example.com", "password": PASSWORD},
    )

    assert response.status_code == 400
    assert client.get("/auth/account").status_code == 302


def test_login_with_correct_credentials_updates_last_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    before_login = datetime.now(UTC) - timedelta(minutes=1)
    user = make_user(email="user@example.com")

    response = _login(client, csrf_token, email="user@example.com")

    assert response.status_code == 302
    assert response.headers["Location"] == "/"

    db.session.refresh(user)
    assert user.last_login_at is not None
    assert user.last_login_at.tzinfo is not None
    assert user.last_login_at >= before_login

    account = client.get("/auth/account")
    assert account.status_code == 200
    html = account.get_data(as_text=True)
    assert "user@example.com" in html
    assert user.password_hash not in html


def test_login_with_incorrect_credentials_uses_generic_error(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")

    wrong_password = _login(
        client,
        csrf_token,
        email="user@example.com",
        password="WrongPass123",
    )
    missing_account = _login(
        client,
        csrf_token,
        email="missing@example.com",
    )

    assert wrong_password.status_code == 200
    assert missing_account.status_code == 200
    assert "Invalid email or password." in wrong_password.get_data(as_text=True)
    assert "Invalid email or password." in missing_account.get_data(as_text=True)
    assert client.get("/auth/account").status_code == 302


def test_inactive_account_cannot_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="inactive@example.com", is_active=False)

    response = _login(client, csrf_token, email="inactive@example.com")

    assert response.status_code == 200
    assert "Invalid email or password." in response.get_data(as_text=True)
    assert client.get("/auth/account").status_code == 302


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/steal",
        "//evil.example/steal",
        r"\evil.example/steal",
        "javascript:alert(1)",
        "/%2f%2fevil.example/steal",
        "/%5cevil.example/steal",
    ],
)
def test_login_rejects_unsafe_next_redirects(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    target: str,
) -> None:
    make_user(email="user@example.com")

    response = _login(client, csrf_token, email="user@example.com", next_url=target)

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_honours_safe_local_next_redirect(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")

    response = _login(
        client,
        csrf_token,
        email="user@example.com",
        next_url="/auth/account",
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/auth/account"
    assert client.get("/auth/account").status_code == 200


def test_logout_is_post_only_and_clears_session(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")
    _login(client, csrf_token, email="user@example.com")

    token = csrf_token("/auth/account")
    response = client.post("/auth/logout", data={"csrf_token": token})

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert client.get("/auth/account").status_code == 302
    assert client.get("/auth/logout").status_code == 405


def test_logout_requires_csrf(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")
    _login(client, csrf_token, email="user@example.com")

    response = client.post("/auth/logout", data={})

    assert response.status_code == 400
    assert client.get("/auth/account").status_code == 200


def test_session_cookie_changes_after_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="user@example.com")
    client.get("/auth/login")
    before_cookie = client.get_cookie("utop14_session")
    assert before_cookie is not None

    _login(client, csrf_token, email="user@example.com")

    after_cookie = client.get_cookie("utop14_session")
    assert after_cookie is not None
    assert before_cookie.value != after_cookie.value


def test_inactive_account_session_is_invalidated(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="user@example.com")
    _login(client, csrf_token, email="user@example.com")
    assert client.get("/auth/account").status_code == 200

    user.is_active = False
    db.session.commit()

    assert client.get("/auth/account").status_code == 302
