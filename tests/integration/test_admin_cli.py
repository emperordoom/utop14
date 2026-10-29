"""Integration tests for secure admin provisioning through the CLI."""

from __future__ import annotations

from collections.abc import Callable

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.extensions import db
from app.models import User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER

ADMIN_PASSWORD = "StrongPass123!"


def test_create_admin_cli_provisions_admin_without_printing_password(app: Flask) -> None:
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["users", "create-admin"],
        input=(f" Admin@Example.COM \nInitial Admin\n{ADMIN_PASSWORD}\n{ADMIN_PASSWORD}\n"),
    )

    assert result.exit_code == 0, result.output
    assert "Admin account created for admin@example.com." in result.output
    assert ADMIN_PASSWORD not in result.output

    user = db.session.scalar(select(User).where(User.email == "admin@example.com"))
    assert user is not None
    assert user.role == ROLE_ADMIN
    assert user.is_active is True
    assert user.full_name == "Initial Admin"
    assert user.verify_password(ADMIN_PASSWORD) is True


def test_create_admin_cli_rejects_duplicate_email(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    make_user(email="taken@example.com", role=ROLE_CUSTOMER)
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["users", "create-admin"],
        input="taken@example.com\n",
    )

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert db.session.scalar(select(func.count(User.id))) == 1


def test_create_admin_cli_refuses_second_admin(
    app: Flask,
    make_user: Callable[..., User],
) -> None:
    make_user(email="admin@example.com", role=ROLE_ADMIN)
    runner = app.test_cli_runner()

    result = runner.invoke(args=["users", "create-admin"], input="")

    assert result.exit_code != 0
    assert "admin account already exists" in result.output.lower()
    assert db.session.scalar(select(func.count(User.id))) == 1


def test_create_admin_cli_rejects_short_password(app: Flask) -> None:
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["users", "create-admin"],
        input="short@example.com\nShort Password\nshort\nshort\n",
    )

    assert result.exit_code != 0
    assert "between 8 and 128" in result.output
    assert db.session.scalar(select(func.count(User.id))) == 0


def test_no_public_admin_registration_route(client: FlaskClient) -> None:
    assert client.get("/admin/register").status_code == 404
    assert client.get("/auth/create-admin").status_code == 404
