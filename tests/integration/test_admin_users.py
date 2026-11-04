"""Integration tests for admin user management."""

from __future__ import annotations

import re

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app.auth import load_user
from app.extensions import db
from app.models import User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.audit import AuditContext
from app.services.user_admin import set_user_active

PASSWORD = "ValidPass123"


def _admin(make_user, *, email: str = "root-admin@example.com", name: str = "Root Admin") -> User:
    return make_user(email=email, full_name=name, role=ROLE_ADMIN)


def _csrf_for(client: FlaskClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def _login_client(client: FlaskClient, email: str) -> None:
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": _csrf_for(client, "/auth/login"),
            "email": email,
            "password": PASSWORD,
        },
    )
    assert response.status_code == 302


def _html(response) -> str:
    return response.get_data(as_text=True)


def _password_hash(user: User) -> str:
    return user.password_hash


def test_admin_can_list_users(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="target@example.com", full_name="Target Customer")
    login(admin.email)

    response = client.get("/admin/users")

    assert response.status_code == 200
    html = _html(response)
    assert target.email in html
    assert target.full_name in html
    assert "Manage" in html
    assert "Users" in html
    assert "password_hash" not in html
    assert "pbkdf2:" not in html
    assert "scrypt:" not in html


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_non_admin_cannot_list_or_view_users(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    role: str,
) -> None:
    actor = make_user(email=f"{role}@example.com", role=role)
    target = make_user(email="private-target@example.com")
    login(actor.email)

    assert client.get("/admin/users").status_code == 403
    assert client.get(f"/admin/users/{target.id}").status_code == 403


def test_anonymous_user_is_redirected_to_login(
    app: Flask,
    client: FlaskClient,
    make_user,
) -> None:
    target = make_user(email="anon-target@example.com")

    response = client.get("/admin/users")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    assert client.get(f"/admin/users/{target.id}").status_code == 302


def test_user_list_paginates(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user, email="pager-admin@example.com")
    for index in range(21):
        make_user(email=f"bulk{index}@example.com", full_name=f"Bulk {index}")
    login(admin.email)

    first = _html(client.get("/admin/users"))
    second = _html(client.get("/admin/users?page=2"))

    assert first.count('class="admin-table__primary"') == 20
    assert second.count('class="admin-table__primary"') == 2
    assert "bulk20@example.com" in first
    assert "bulk20@example.com" not in second
    assert "bulk0@example.com" in second
    assert 'aria-label="Pagination"' in first


def test_user_list_search_and_filters(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user, email="filter-admin@example.com")
    customer = make_user(
        email="searchable@example.com",
        full_name="Searchable Buyer",
        role=ROLE_CUSTOMER,
    )
    operator = make_user(
        email="operator-one@example.com",
        full_name="Operator One",
        role=ROLE_OPERATOR,
    )
    dormant = make_user(
        email="dormant@example.com",
        full_name="Dormant User",
        is_active=False,
    )
    login(admin.email)

    name_html = _html(client.get("/admin/users?q=Searchable"))
    assert customer.email in name_html
    assert operator.email not in name_html

    email_html = _html(client.get("/admin/users?q=operator-one"))
    assert operator.email in email_html
    assert customer.email not in email_html

    role_html = _html(client.get("/admin/users?role=operator"))
    assert operator.email in role_html
    assert customer.email not in role_html
    assert dormant.email not in role_html

    status_html = _html(client.get("/admin/users?status=inactive"))
    assert dormant.email in status_html
    assert customer.email not in status_html

    combined = _html(client.get("/admin/users?role=customer&status=inactive"))
    assert dormant.email in combined
    assert customer.email not in combined


def test_user_list_escapes_like_wildcards(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user, email="escape-admin@example.com")
    target = make_user(email="plain@example.com", full_name="Plain User")
    login(admin.email)

    html = _html(client.get("/admin/users?q=%25"))

    assert target.email not in html
    assert "No matches" in html


def test_user_detail_shows_allowed_fields_only(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(
        email="detail@example.com",
        full_name="Detail Person",
        role=ROLE_OPERATOR,
    )
    login(admin.email)

    response = client.get(f"/admin/users/{target.id}")

    assert response.status_code == 200
    html = _html(response)
    assert "Detail Person" in html
    assert target.email in html
    assert "Operator" in html
    assert "Active" in html
    assert "password_hash" not in html
    assert "scrypt:" not in html
    assert "pbkdf2:" not in html


def test_unknown_user_detail_returns_404(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    login(admin.email)

    assert client.get("/admin/users/999999").status_code == 404


def test_admin_updates_profile_without_touching_password(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="before@example.com", full_name="Before Name")
    original_hash = _password_hash(target)
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "  After Name  ",
            "email": "  AFTER@Example.COM ",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.refresh(target)
    assert target.full_name == "After Name"
    assert target.email == "after@example.com"
    assert target.password_hash == original_hash
    assert target.role == ROLE_CUSTOMER
    assert target.is_active is True
    assert "Account details updated." in _html(response)


def test_admin_updates_own_profile_but_not_role_or_status(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user, email="self-edit@example.com", name="Self Edit")
    login(admin.email)

    client.post(
        f"/admin/users/{admin.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{admin.id}"),
            "full_name": "Self Edited",
            "email": "self-edited@example.com",
            "role": "customer",
            "is_active": "false",
        },
    )

    db.session.refresh(admin)
    assert admin.full_name == "Self Edited"
    assert admin.email == "self-edited@example.com"
    assert admin.role == ROLE_ADMIN
    assert admin.is_active is True


def test_profile_update_rejects_duplicate_email(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    first = make_user(email="first@example.com", full_name="First")
    second = make_user(email="second@example.com", full_name="Second")
    login(admin.email)

    response = client.post(
        f"/admin/users/{first.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{first.id}"),
            "full_name": "First",
            "email": "second@example.com",
        },
        follow_redirects=True,
    )

    db.session.refresh(first)
    db.session.refresh(second)
    assert first.email == "first@example.com"
    assert second.email == "second@example.com"
    assert "already exists" in _html(response)


@pytest.mark.parametrize(
    ("full_name", "email"),
    [
        ("", "valid@example.com"),
        ("   ", "valid@example.com"),
        ("Valid Name", "not-an-email"),
        ("a" * 121, "valid@example.com"),
    ],
)
def test_profile_update_rejects_invalid_input(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    full_name: str,
    email: str,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="unchanged@example.com", full_name="Unchanged")
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": full_name,
            "email": email,
        },
    )

    db.session.refresh(target)
    assert target.full_name == "Unchanged"
    assert target.email == "unchanged@example.com"


def test_profile_update_ignores_mass_assignment_fields(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="mass@example.com", full_name="Mass Target")
    original_hash = _password_hash(target)
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Mass Updated",
            "email": "mass-updated@example.com",
            "role": "admin",
            "is_active": "false",
            "password": "HackedPass123",
            "password_hash": "injected",
            "avatar_filename": "evil.webp",
        },
    )

    db.session.refresh(target)
    assert target.full_name == "Mass Updated"
    assert target.email == "mass-updated@example.com"
    assert target.role == ROLE_CUSTOMER
    assert target.is_active is True
    assert target.password_hash == original_hash
    assert target.avatar_filename is None


def test_admin_deactivates_and_activates_user(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="toggle@example.com")
    login(admin.email)

    deactivate = client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )
    db.session.refresh(target)
    assert target.is_active is False
    assert "Account deactivated." in _html(deactivate)
    assert load_user(str(target.id)) is None

    activate = client.post(
        f"/admin/users/{target.id}/activate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )
    db.session.refresh(target)
    assert target.is_active is True
    assert "Account activated." in _html(activate)
    assert load_user(str(target.id)) is not None


def test_deactivation_invalidates_existing_session(
    app: Flask,
    make_user,
) -> None:
    admin = _admin(make_user)
    customer = make_user(email="session-customer@example.com")
    customer_client = app.test_client()
    _login_client(customer_client, customer.email)
    assert customer_client.get("/auth/account").status_code == 200

    set_user_active(
        admin.id,
        customer.id,
        is_active=False,
        audit_context=AuditContext(
            actor_id=admin.id,
            actor_email=admin.email,
            ip_address="127.0.0.1",
            user_agent="pytest",
            request_id="a" * 32,
        ),
    )

    response = customer_client.get("/auth/account")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_role_management_promotes_and_demotes(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="role-target@example.com", role=ROLE_CUSTOMER)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")

    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
    )
    db.session.refresh(target)
    assert target.role == ROLE_OPERATOR

    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_ADMIN},
    )
    db.session.refresh(target)
    assert target.role == ROLE_ADMIN

    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_CUSTOMER},
    )
    db.session.refresh(target)
    assert target.role == ROLE_CUSTOMER


def test_invalid_role_is_rejected(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="bad-role@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/role",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "role": "owner",
        },
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.role == ROLE_CUSTOMER
    assert "valid role" in _html(response)


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_non_admin_cannot_change_role(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    role: str,
) -> None:
    actor = make_user(email=f"role-{role}@example.com", role=role)
    target = make_user(email="role-protected@example.com")
    login(actor.email)
    token = _csrf_for(client, "/auth/account")

    response = client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_ADMIN},
    )

    db.session.refresh(target)
    assert response.status_code == 403
    assert target.role == ROLE_CUSTOMER


def test_sole_admin_cannot_deactivate_self(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user, email="sole-admin@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{admin.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{admin.id}")},
        follow_redirects=True,
    )

    db.session.refresh(admin)
    assert admin.is_active is True
    assert admin.role == ROLE_ADMIN
    assert "cannot remove your own administrative access" in _html(response)


def test_sole_admin_cannot_demote_self(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user, email="sole-demote@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{admin.id}/role",
        data={
            "csrf_token": csrf_token(f"/admin/users/{admin.id}"),
            "role": ROLE_CUSTOMER,
        },
        follow_redirects=True,
    )

    db.session.refresh(admin)
    assert admin.role == ROLE_ADMIN
    assert "cannot remove your own administrative access" in _html(response)


def test_admin_cannot_deactivate_self_even_with_another_admin(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    first = _admin(make_user, email="self-one@example.com")
    _admin(make_user, email="self-two@example.com")
    login(first.email)

    response = client.post(
        f"/admin/users/{first.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{first.id}")},
        follow_redirects=True,
    )

    db.session.refresh(first)
    assert first.is_active is True
    assert "cannot remove your own administrative access" in _html(response)


def test_admin_can_deactivate_other_admin_when_one_remains(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    actor = _admin(make_user, email="remaining-admin@example.com")
    target = _admin(make_user, email="other-admin@example.com")
    login(actor.email)

    response = client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )

    db.session.refresh(actor)
    db.session.refresh(target)
    assert actor.is_active is True
    assert target.is_active is False
    assert "Account deactivated." in _html(response)


def test_admin_can_demote_other_admin_when_one_remains(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    actor = _admin(make_user, email="remaining-role-admin@example.com")
    target = _admin(make_user, email="demote-admin@example.com")
    login(actor.email)

    client.post(
        f"/admin/users/{target.id}/role",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "role": ROLE_OPERATOR,
        },
    )

    db.session.refresh(actor)
    db.session.refresh(target)
    assert actor.role == ROLE_ADMIN
    assert target.role == ROLE_OPERATOR


@pytest.mark.parametrize("action", ["profile", "role", "activate", "deactivate"])
def test_state_changing_routes_require_csrf(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    action: str,
) -> None:
    admin = _admin(make_user)
    target = make_user(email=f"csrf-{action}@example.com")
    login(admin.email)

    payload = {
        "profile": {"full_name": "No Token", "email": "no-token@example.com"},
        "role": {"role": ROLE_ADMIN},
        "activate": {},
        "deactivate": {},
    }[action]
    response = client.post(f"/admin/users/{target.id}/{action}", data=payload)

    assert response.status_code == 400
    db.session.refresh(target)
    assert target.email == f"csrf-{action}@example.com"
    assert target.role == ROLE_CUSTOMER
    assert target.is_active is True


def test_no_destructive_delete_route_exists(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="no-delete@example.com")
    login(admin.email)

    assert client.get(f"/admin/users/{target.id}/delete").status_code == 404
    assert client.post(f"/admin/users/{target.id}/delete").status_code == 404
    assert db.session.get(User, target.id) is not None


def test_inactive_status_change_is_a_noop(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="already-inactive@example.com", is_active=False)
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.is_active is False
    assert "already inactive" in _html(response)
