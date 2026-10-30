"""Integration tests for customer profile management and privacy."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from flask.testing import FlaskClient
from sqlalchemy import select

from app.extensions import db
from app.models import User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER

PASSWORD = "ValidPass123"


def _post_profile(
    client: FlaskClient,
    token_for: Callable[[str], str],
    *,
    full_name: str,
    email: str,
    extra: dict[str, str] | None = None,
    include_csrf: bool = True,
    follow_redirects: bool = True,
) -> object:
    data = {"full_name": full_name, "email": email}
    if include_csrf:
        data["csrf_token"] = token_for("/auth/account")
    if extra:
        data.update(extra)
    return client.post(
        "/auth/account/profile",
        data=data,
        follow_redirects=follow_redirects,
    )


def test_customer_can_view_own_profile_and_avatar_controls(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="profile-view@example.com", full_name="Test Customer")
    login(user.email)

    response = client.get("/auth/account")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Account details" in html
    assert "Save profile" in html
    assert "Upload avatar" in html
    assert "JPEG, PNG or WebP" in html
    assert "Maximum 2 MB" in html
    assert "/static/js/account.js" in html
    assert "Remove avatar" not in html
    assert "TC" in html
    assert user.password_hash not in html
    assert PASSWORD not in html


def test_customer_can_update_own_name_and_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="profile-update@example.com", full_name="Old Name")

    login(user.email)
    response = _post_profile(
        client,
        csrf_token,
        full_name="New Name",
        email="new.profile@example.com",
    )

    assert response.status_code == 200
    assert "Profile updated." in response.get_data(as_text=True)

    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.full_name == "New Name"
    assert refreshed.email == "new.profile@example.com"
    assert refreshed.role == ROLE_CUSTOMER
    assert refreshed.is_active is True
    assert refreshed.verify_password(PASSWORD) is True


def test_profile_normalizes_whitespace_and_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="normalize-profile@example.com")
    login(user.email)

    _post_profile(
        client,
        csrf_token,
        full_name="  Ada   Lovelace  ",
        email="  ADA.LOVELACE@Example.COM ",
    )

    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.full_name == "Ada Lovelace"
    assert refreshed.email == "ada.lovelace@example.com"


def test_profile_rejects_duplicate_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="profile-owner@example.com")
    make_user(email="taken@example.com", full_name="Other User")
    login(user.email)

    response = _post_profile(
        client,
        csrf_token,
        full_name="Profile Owner",
        email=" TAKEN@example.com ",
    )

    assert response.status_code == 200
    assert "already exists" in response.get_data(as_text=True)
    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.email == "profile-owner@example.com"


def test_profile_rejects_invalid_email(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="invalid-email-profile@example.com")
    login(user.email)

    response = _post_profile(
        client,
        csrf_token,
        full_name="Still Valid",
        email="not-an-email",
    )

    assert response.status_code == 200
    assert "Invalid email address." in response.get_data(as_text=True)
    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.email == "invalid-email-profile@example.com"


def test_profile_rejects_empty_name(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., User],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="empty-name-profile@example.com", full_name="Keep Me")
    login(user.email)

    response = _post_profile(
        client,
        csrf_token,
        full_name="   ",
        email=user.email,
    )

    assert response.status_code == 200
    assert "This field is required." in response.get_data(as_text=True)
    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.full_name == "Keep Me"


def test_profile_ignores_internal_fields_and_other_user_targets(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    owner = make_user(email="profile-fields-owner@example.com", full_name="Owner")
    other = make_user(email="profile-fields-other@example.com", full_name="Other")
    original_owner_hash = owner.password_hash
    original_other_hash = other.password_hash
    login(owner.email)

    response = _post_profile(
        client,
        csrf_token,
        full_name="Owner Updated",
        email="owner.updated@example.com",
        extra={
            "id": str(other.id),
            "user_id": str(other.id),
            "role": ROLE_ADMIN,
            "is_active": "false",
            "password_hash": "attacker-controlled",
        },
    )

    assert response.status_code == 200
    db.session.expire_all()
    refreshed_owner = db.session.get(User, owner.id)
    refreshed_other = db.session.get(User, other.id)
    assert refreshed_owner is not None
    assert refreshed_other is not None
    assert refreshed_owner.full_name == "Owner Updated"
    assert refreshed_owner.email == "owner.updated@example.com"
    assert refreshed_owner.role == ROLE_CUSTOMER
    assert refreshed_owner.is_active is True
    assert refreshed_owner.password_hash == original_owner_hash
    assert refreshed_other.full_name == "Other"
    assert refreshed_other.email == "profile-fields-other@example.com"
    assert refreshed_other.role == ROLE_CUSTOMER
    assert refreshed_other.is_active is True
    assert refreshed_other.password_hash == original_other_hash


def test_profile_update_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="profile-csrf@example.com", full_name="No Change")
    login(user.email)

    response = _post_profile(
        client,
        lambda _path: "",
        full_name="Changed",
        email="changed@example.com",
        include_csrf=False,
        follow_redirects=False,
    )

    assert response.status_code == 400
    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    assert refreshed.full_name == "No Change"
    assert refreshed.email == "profile-csrf@example.com"


@pytest.mark.parametrize("path", ["/auth/account", "/auth/avatar"])
def test_profile_pages_require_login(client: FlaskClient, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_profile_mutation_requires_login(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
) -> None:
    token = csrf_token("/auth/login")

    response = client.post(
        "/auth/account/profile",
        data={
            "csrf_token": token,
            "full_name": "Anonymous",
            "email": "anonymous@example.com",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


def test_profile_does_not_change_email_of_another_user(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    first = make_user(email="first-profile@example.com")
    second = make_user(email="second-profile@example.com")
    login(first.email)

    _post_profile(
        client,
        csrf_token,
        full_name=first.full_name,
        email="first-updated@example.com",
    )

    db.session.expire_all()
    refreshed_second = db.session.get(User, second.id)
    assert refreshed_second is not None
    assert refreshed_second.email == "second-profile@example.com"
    assert db.session.scalar(select(User).where(User.email == "first-updated@example.com"))
