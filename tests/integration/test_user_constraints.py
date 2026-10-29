"""PostgreSQL-backed tests for User constraints and defaults."""

from __future__ import annotations

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import User
from app.models.user import ROLE_CUSTOMER


def _user(email: str, *, role: str = ROLE_CUSTOMER) -> User:
    user = User(email=email, full_name="Test User", role=role)
    user.set_password("ValidPass123")
    return user


def test_email_uniqueness_is_case_insensitive_after_normalization(app: Flask) -> None:
    db.session.add(_user("first@example.com"))
    db.session.commit()

    db.session.add(_user("  FIRST@Example.COM "))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    assert db.session.scalar(select(User).where(User.email == "first@example.com")) is not None


def test_database_rejects_unknown_roles(app: Flask) -> None:
    db.session.add(_user("owner@example.com", role="owner"))

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    assert db.session.scalar(select(User).where(User.email == "owner@example.com")) is None


def test_default_role_active_state_and_get_id(app: Flask) -> None:
    user = User(email="default@example.com", full_name="Default User")
    user.set_password("ValidPass123")
    db.session.add(user)
    db.session.commit()

    assert user.role == ROLE_CUSTOMER
    assert user.is_active is True
    assert user.last_login_at is None
    assert user.get_id() == str(user.id)
