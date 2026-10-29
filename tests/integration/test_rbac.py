"""Integration tests for server-side role-based access control."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from flask.testing import FlaskClient
from werkzeug.wrappers import Response

from app.auth.permissions import role_required
from app.models import User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR

PASSWORD = "ValidPass123"


def _login_as(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    email: str,
) -> Response:
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": token_for("/auth/login"),
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 302
    return response


@pytest.mark.parametrize("path", ["/admin", "/ops", "/auth/account"])
def test_unauthenticated_users_are_redirected_to_login(
    client: FlaskClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith("/auth/login")
    assert "next=" in location


@pytest.mark.parametrize(
    ("role", "path", "expected"),
    [
        (ROLE_CUSTOMER, "/auth/account", 200),
        (ROLE_CUSTOMER, "/ops", 403),
        (ROLE_CUSTOMER, "/admin", 403),
        (ROLE_OPERATOR, "/auth/account", 200),
        (ROLE_OPERATOR, "/ops", 200),
        (ROLE_OPERATOR, "/admin", 403),
        (ROLE_ADMIN, "/auth/account", 200),
        (ROLE_ADMIN, "/ops", 200),
        (ROLE_ADMIN, "/admin", 200),
    ],
)
def test_role_access_matrix(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
    role: str,
    path: str,
    expected: int,
) -> None:
    make_user(email=f"{role}@example.com", role=role)
    _login_as(client, csrf_token, email=f"{role}@example.com")

    assert client.get(path).status_code == expected


def test_customer_receives_branded_403_on_admin_dashboard(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="customer@example.com", role=ROLE_CUSTOMER)
    _login_as(client, csrf_token, email="customer@example.com")

    response = client.get("/admin")

    assert response.status_code == 403
    html = response.get_data(as_text=True)
    assert "403 / Restricted signal" in html
    assert "This area is" in html
    assert "off limits" in html
    assert "/static/css/catalog.css" in html


def test_admin_dashboard_renders_aggregate_counts(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="admin@example.com", role=ROLE_ADMIN)
    _login_as(client, csrf_token, email="admin@example.com")

    response = client.get("/admin")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Admin / Control room" in html
    assert "Inventory" in html
    assert "Role" in html
    assert "password_hash" not in html


def test_operator_console_renders_without_admin_navigation(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    make_user: Callable[..., User],
) -> None:
    make_user(email="operator@example.com", role=ROLE_OPERATOR)
    _login_as(client, csrf_token, email="operator@example.com")

    response = client.get("/ops")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Operator / Floor view" in html
    assert "Operator scope" in html


def test_role_required_rejects_unknown_role_names() -> None:
    with pytest.raises(ValueError, match="Unknown role"):
        role_required("owner")
