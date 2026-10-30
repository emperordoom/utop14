"""Unit tests for user password and role helpers."""

from __future__ import annotations

import pytest

from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR, User


def _user(role: str = ROLE_CUSTOMER) -> User:
    return User(
        email="  Person@Example.COM ",
        full_name="Test Person",
        role=role,
    )


def test_email_is_normalized_on_assignment() -> None:
    user = _user()
    assert user.email == "person@example.com"


def test_password_is_hashed_and_verifiable() -> None:
    user = _user()
    password = "ValidPass123"

    user.set_password(password)

    assert user.password_hash
    assert user.password_hash != password
    assert password not in user.password_hash
    assert user.verify_password(password) is True
    assert user.verify_password("WrongPass123") is False


def test_empty_password_is_rejected() -> None:
    with pytest.raises(ValueError, match="Password"):
        _user().set_password("   ")


def test_role_hierarchy() -> None:
    customer = _user(ROLE_CUSTOMER)
    operator = _user(ROLE_OPERATOR)
    admin = _user(ROLE_ADMIN)

    assert customer.has_role(ROLE_CUSTOMER) is True
    assert customer.has_role(ROLE_OPERATOR) is False
    assert customer.has_role(ROLE_ADMIN) is False

    assert operator.has_role(ROLE_CUSTOMER) is True
    assert operator.has_role(ROLE_OPERATOR) is True
    assert operator.has_role(ROLE_ADMIN) is False
    assert operator.is_operator is True
    assert operator.is_admin is False

    assert admin.has_role(ROLE_CUSTOMER) is True
    assert admin.has_role(ROLE_OPERATOR) is True
    assert admin.has_role(ROLE_ADMIN) is True
    assert admin.is_operator is True
    assert admin.is_admin is True


def test_unknown_role_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown role"):
        _user().has_role("owner")


def test_repr_does_not_include_password_material() -> None:
    user = _user()
    user.set_password("ValidPass123")

    representation = repr(user)

    assert "person@example.com" in representation
    assert "customer" in representation
    assert "password" not in representation.lower()
    assert user.password_hash not in representation


def test_initials_use_up_to_two_name_parts() -> None:
    assert User(full_name="Test Person").initials == "TP"
    assert User(full_name="Ada").initials == "A"
    assert User(full_name="Ada Byron Lovelace").initials == "AB"
    assert User(full_name="   ").initials == "U"
