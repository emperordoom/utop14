"""Transaction atomicity tests for User mutation + audit insertion."""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.extensions import db
from app.models import AuditLog, User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR


def _admin(make_user) -> User:
    return make_user(
        email="atomic-admin@example.com",
        full_name="Atomic Admin",
        role=ROLE_ADMIN,
    )


def _audit_count() -> int:
    return db.session.scalar(select(func.count(AuditLog.id))) or 0


def _fail_audit_insert(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args, **_kwargs):
        raise SQLAlchemyError("simulated audit insert failure")

    monkeypatch.setattr("app.services.user_admin.record_audit_event", _raise)


def test_profile_update_rolls_back_when_audit_insert_fails(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="atomic-profile@example.com", full_name="Before Name")
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    _fail_audit_insert(monkeypatch)

    response = client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": token,
            "full_name": "After Name",
            "email": "after-email@example.com",
        },
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.full_name == "Before Name"
    assert target.email == "atomic-profile@example.com"
    assert _audit_count() == 0
    assert response.status_code == 200
    assert "could not be saved" in response.get_data(as_text=True)


def test_role_change_rolls_back_when_audit_insert_fails(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="atomic-role@example.com", role=ROLE_CUSTOMER)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    _fail_audit_insert(monkeypatch)

    response = client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.role == ROLE_CUSTOMER
    assert _audit_count() == 0
    assert response.status_code == 200
    assert "could not be updated" in response.get_data(as_text=True)


def test_deactivation_rolls_back_when_audit_insert_fails(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="atomic-deactivate@example.com")
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    _fail_audit_insert(monkeypatch)

    response = client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.is_active is True
    assert _audit_count() == 0
    assert response.status_code == 200
    assert "could not be updated" in response.get_data(as_text=True)


def test_audit_flush_failure_rolls_back_user_and_audit(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="flush-failure@example.com", full_name="Before Flush")
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    target_id = target.id
    real_flush = Session.flush

    def failing_flush(self, *args, **kwargs):
        if any(isinstance(item, AuditLog) for item in self.new):
            raise SQLAlchemyError("simulated audit flush failure")
        return real_flush(self, *args, **kwargs)

    monkeypatch.setattr(Session, "flush", failing_flush)

    response = client.post(
        f"/admin/users/{target_id}/profile",
        data={
            "csrf_token": token,
            "full_name": "After Flush",
            "email": "after-flush@example.com",
        },
        follow_redirects=True,
    )

    db.session.remove()
    persisted = db.session.get(User, target_id)
    assert persisted is not None
    assert persisted.full_name == "Before Flush"
    assert persisted.email == "flush-failure@example.com"
    assert _audit_count() == 0
    body = response.get_data(as_text=True).lower()
    assert "could not be saved" in body
    assert "sqlalchemy" not in body
    assert "audit_logs" not in body


def test_activation_rolls_back_when_audit_insert_fails(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="atomic-activate@example.com", is_active=False)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    _fail_audit_insert(monkeypatch)

    response = client.post(
        f"/admin/users/{target.id}/activate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    db.session.refresh(target)
    assert target.is_active is False
    assert _audit_count() == 0
    assert response.status_code == 200
    assert "could not be updated" in response.get_data(as_text=True)


def test_final_commit_failure_rolls_back_user_and_audit(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="commit-failure@example.com", role=ROLE_CUSTOMER)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")
    target_id = target.id
    real_commit = Session.commit
    failed = {"raised": False}

    def failing_commit(self, *args, **kwargs):
        if not failed["raised"]:
            failed["raised"] = True
            raise SQLAlchemyError("simulated final commit failure")
        return real_commit(self, *args, **kwargs)

    monkeypatch.setattr(Session, "commit", failing_commit)

    response = client.post(
        f"/admin/users/{target_id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
        follow_redirects=True,
    )

    db.session.remove()
    persisted = db.session.get(User, target_id)
    assert persisted is not None
    assert persisted.role == ROLE_CUSTOMER
    assert _audit_count() == 0
    body = response.get_data(as_text=True).lower()
    assert "could not be updated" in body
    assert "sqlalchemy" not in body
    assert "audit_logs" not in body
