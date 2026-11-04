"""Integration tests for administrative audit logging and viewing."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import db
from app.models import AuditLog, User
from app.models.audit_log import (
    AUDIT_ACTION_ACTIVATED,
    AUDIT_ACTION_DEACTIVATED,
    AUDIT_ACTION_PROFILE_UPDATED,
    AUDIT_ACTION_ROLE_CHANGED,
)
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR

PASSWORD = "ValidPass123"


def _admin(
    make_user,
    *,
    email: str = "audit-admin@example.com",
    name: str = "Audit Admin",
) -> User:
    return make_user(email=email, full_name=name, role=ROLE_ADMIN)


def _audit_rows() -> list[AuditLog]:
    return list(db.session.scalars(select(AuditLog).order_by(AuditLog.id)).all())


def _audit_count() -> int:
    return db.session.scalar(select(func.count(AuditLog.id))) or 0


def _add_log(
    actor: User,
    target: User,
    *,
    action: str = AUDIT_ACTION_ROLE_CHANGED,
    before: dict | None = None,
    after: dict | None = None,
    created_at: datetime | None = None,
    request_id: str | None = None,
) -> AuditLog:
    kwargs = {
        "actor_id": actor.id,
        "actor_email": actor.email,
        "target_user_id": target.id,
        "target_email": target.email,
        "action": action,
        "before_data": before or {"role": ROLE_CUSTOMER},
        "after_data": after or {"role": ROLE_OPERATOR},
        "ip_address": "127.0.0.1",
        "user_agent": "pytest",
        "request_id": request_id or uuid4().hex,
    }
    if created_at is not None:
        kwargs["created_at"] = created_at
    log = AuditLog(**kwargs)
    db.session.add(log)
    db.session.commit()
    return log


def _assert_common_metadata(
    log: AuditLog,
    *,
    admin: User,
    target: User,
    action: str,
    before: dict,
    after: dict,
) -> None:
    assert log.action == action
    assert log.actor_id == admin.id
    assert log.actor_email == admin.email
    assert log.target_user_id == target.id
    assert str(log.ip_address) == "127.0.0.1"
    assert log.user_agent
    assert log.request_id is not None
    assert len(log.request_id) == 32
    assert log.created_at.tzinfo is not None
    assert log.before_data == before
    assert log.after_data == after


def test_profile_update_records_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(
        email="profile-target@example.com",
        full_name="Profile Target",
    )
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Profile Updated",
            "email": "profile-updated@example.com",
        },
    )

    assert response.status_code == 302
    log = db.session.scalar(select(AuditLog))
    assert log is not None
    _assert_common_metadata(
        log,
        admin=admin,
        target=target,
        action=AUDIT_ACTION_PROFILE_UPDATED,
        before={
            "full_name": "Profile Target",
            "email": "profile-target@example.com",
        },
        after={
            "full_name": "Profile Updated",
            "email": "profile-updated@example.com",
        },
    )
    assert log.target_email == "profile-updated@example.com"
    assert log.request_id == response.headers["X-Request-ID"]


def test_role_change_records_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="role-target@example.com", role=ROLE_CUSTOMER)
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/role",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "role": ROLE_OPERATOR,
        },
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    _assert_common_metadata(
        log,
        admin=admin,
        target=target,
        action=AUDIT_ACTION_ROLE_CHANGED,
        before={"role": ROLE_CUSTOMER},
        after={"role": ROLE_OPERATOR},
    )


def test_activation_records_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="activate-target@example.com", is_active=False)
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/activate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    _assert_common_metadata(
        log,
        admin=admin,
        target=target,
        action=AUDIT_ACTION_ACTIVATED,
        before={"is_active": False},
        after={"is_active": True},
    )


def test_deactivation_records_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="deactivate-target@example.com")
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    _assert_common_metadata(
        log,
        admin=admin,
        target=target,
        action=AUDIT_ACTION_DEACTIVATED,
        before={"is_active": True},
        after={"is_active": False},
    )


def test_profile_noop_does_not_create_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="noop-profile@example.com", full_name="Same Name")
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Same Name",
            "email": "noop-profile@example.com",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert _audit_count() == 0
    assert "No account changes" in response.get_data(as_text=True)


def test_role_noop_does_not_create_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="noop-role@example.com", role=ROLE_CUSTOMER)
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/role",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "role": ROLE_CUSTOMER,
        },
        follow_redirects=True,
    )

    assert "already has" in response.get_data(as_text=True)
    assert _audit_count() == 0


def test_activation_noop_does_not_create_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="noop-active@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/activate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )

    assert "already active" in response.get_data(as_text=True)
    assert _audit_count() == 0


def test_deactivation_noop_does_not_create_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="noop-inactive@example.com", is_active=False)
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/deactivate",
        data={"csrf_token": csrf_token(f"/admin/users/{target.id}")},
        follow_redirects=True,
    )

    assert "already inactive" in response.get_data(as_text=True)
    assert _audit_count() == 0


def test_sequential_duplicate_transition_creates_one_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="duplicate-event@example.com", role=ROLE_CUSTOMER)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")

    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
    )
    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
    )

    assert _audit_count() == 1


def test_two_distinct_role_changes_create_two_events(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="two-changes@example.com", role=ROLE_CUSTOMER)
    login(admin.email)
    token = csrf_token(f"/admin/users/{target.id}")

    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_OPERATOR},
    )
    client.post(
        f"/admin/users/{target.id}/role",
        data={"csrf_token": token, "role": ROLE_ADMIN},
    )

    logs = _audit_rows()
    assert len(logs) == 2
    assert logs[0].before_data == {"role": ROLE_CUSTOMER}
    assert logs[0].after_data == {"role": ROLE_OPERATOR}
    assert logs[1].before_data == {"role": ROLE_OPERATOR}
    assert logs[1].after_data == {"role": ROLE_ADMIN}


def test_sensitive_snapshot_data_excluded_from_audit_and_pages(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(
        email="sensitive-target@example.com",
        full_name="Sensitive Target",
    )
    target.set_password(PASSWORD)
    db.session.commit()
    password_hash = target.password_hash
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Sensitive Updated",
            "email": "sensitive-updated@example.com",
        },
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    serialized = json.dumps({"before": log.before_data, "after": log.after_data})
    for forbidden in (
        "password",
        "password_hash",
        "session",
        "csrf",
        "token",
        "secret",
        password_hash,
    ):
        assert forbidden not in serialized.lower()

    list_html = client.get("/admin/audit-logs").get_data(as_text=True)
    detail_html = client.get(f"/admin/audit-logs/{log.id}").get_data(as_text=True)
    for html in (list_html, detail_html):
        assert "password" not in html.lower()
        assert password_hash not in html


def test_audit_detail_escapes_snapshot_html(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="xss-target@example.com", full_name="Safe Name")
    login(admin.email)
    payload = "<script>alert(1)</script>"

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": payload,
            "email": target.email,
        },
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    html = client.get(f"/admin/audit-logs/{log.id}").get_data(as_text=True)
    assert payload not in html
    assert "\\u003cscript\\u003e" in html


def test_admin_can_view_audit_list_and_detail(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="view-target@example.com")
    log = _add_log(admin, target)
    login(admin.email)

    list_response = client.get("/admin/audit-logs")
    detail_response = client.get(f"/admin/audit-logs/{log.id}")

    assert list_response.status_code == 200
    assert target.email in list_response.get_data(as_text=True)
    assert detail_response.status_code == 200
    detail_html = detail_response.get_data(as_text=True)
    assert "Role changed" in detail_html
    assert "Before" in detail_html
    assert "After" in detail_html
    assert 'action="/admin/audit-logs' not in detail_html


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_non_admin_cannot_view_audit_logs(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    role: str,
) -> None:
    actor = make_user(email=f"audit-{role}@example.com", role=role)
    admin = _admin(make_user)
    target = make_user(email=f"audit-target-{role}@example.com")
    log = _add_log(admin, target)
    login(actor.email)

    assert client.get("/admin/audit-logs").status_code == 403
    assert client.get(f"/admin/audit-logs/{log.id}").status_code == 403


def test_anonymous_user_is_redirected_to_login(
    app: Flask,
    client: FlaskClient,
    make_user,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="anon-audit-target@example.com")
    log = _add_log(admin, target)

    response = client.get("/admin/audit-logs")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    assert client.get(f"/admin/audit-logs/{log.id}").status_code == 302


def test_audit_logs_have_no_mutation_routes(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="immutable-target@example.com")
    log = _add_log(admin, target)
    login(admin.email)
    before = _audit_count()

    assert client.post("/admin/audit-logs").status_code == 405
    assert client.post(f"/admin/audit-logs/{log.id}").status_code == 405
    assert client.put(f"/admin/audit-logs/{log.id}").status_code == 405
    assert client.delete(f"/admin/audit-logs/{log.id}").status_code == 405
    assert client.get(f"/admin/audit-logs/{log.id}/delete").status_code == 404
    assert client.post(f"/admin/audit-logs/{log.id}/delete").status_code == 404
    assert _audit_count() == before


def test_audit_filters_action_actor_target_and_query(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user, name="Filter Admin")
    first = make_user(email="first-target@example.com", full_name="First Target")
    second = make_user(email="second-target@example.com", full_name="Second Target")
    _add_log(
        admin,
        first,
        action=AUDIT_ACTION_ROLE_CHANGED,
        before={"role": ROLE_CUSTOMER},
        after={"role": ROLE_OPERATOR},
    )
    _add_log(
        admin,
        second,
        action=AUDIT_ACTION_ACTIVATED,
        before={"is_active": False},
        after={"is_active": True},
    )
    login(admin.email)

    action_html = client.get(f"/admin/audit-logs?action={AUDIT_ACTION_ACTIVATED}").get_data(
        as_text=True
    )
    assert second.email in action_html
    assert first.email not in action_html

    actor_html = client.get("/admin/audit-logs?actor=Filter%20Admin").get_data(as_text=True)
    assert first.email in actor_html
    assert second.email in actor_html

    target_html = client.get("/admin/audit-logs?target=First%20Target").get_data(as_text=True)
    assert first.email in target_html
    assert second.email not in target_html

    query_html = client.get("/admin/audit-logs?q=second-target").get_data(as_text=True)
    assert second.email in query_html
    assert first.email not in query_html

    combined = client.get(
        f"/admin/audit-logs?action={AUDIT_ACTION_ROLE_CHANGED}&target=first-target"
    ).get_data(as_text=True)
    assert first.email in combined
    assert second.email not in combined


def test_audit_filters_date_range(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="date-target@example.com")
    now = datetime.now(UTC)
    _add_log(admin, target, created_at=now - timedelta(days=1))
    _add_log(admin, target, created_at=now)
    _add_log(admin, target, created_at=now + timedelta(days=1))
    login(admin.email)
    today = now.date().isoformat()

    html = client.get(f"/admin/audit-logs?date_from={today}&date_to={today}").get_data(as_text=True)

    assert html.count('class="audit-action') == 1


def test_audit_filter_escapes_like_wildcards(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="percent-target@example.com")
    _add_log(admin, target)
    login(admin.email)

    html = client.get("/admin/audit-logs?q=%25").get_data(as_text=True)

    assert target.email not in html
    assert "No changes in this" in html


def test_audit_list_paginates_twenty_per_page(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="pager-target@example.com")
    now = datetime.now(UTC)
    for index in range(21):
        _add_log(admin, target, created_at=now - timedelta(minutes=index))
    login(admin.email)

    first = client.get("/admin/audit-logs").get_data(as_text=True)
    second = client.get("/admin/audit-logs?page=2").get_data(as_text=True)

    assert first.count('class="audit-action') == 20
    assert second.count('class="audit-action') == 1
    assert 'aria-label="Pagination"' in first


def test_audit_list_is_newest_first(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
) -> None:
    admin = _admin(make_user)
    old_target = make_user(email="older@example.com")
    new_target = make_user(email="newer@example.com")
    now = datetime.now(UTC)
    _add_log(admin, old_target, created_at=now - timedelta(hours=2))
    _add_log(admin, new_target, created_at=now)
    login(admin.email)

    html = client.get("/admin/audit-logs").get_data(as_text=True)

    assert html.index(new_target.email) < html.index(old_target.email)


def test_spoofed_forwarded_header_is_ignored_without_trusted_proxy(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="spoof-target@example.com")
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Spoof Updated",
            "email": target.email,
        },
        headers={"X-Forwarded-For": "203.0.113.9"},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    assert str(log.ip_address) == "127.0.0.1"


def test_proxy_fix_records_client_ip_when_explicitly_configured(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    admin = _admin(make_user)
    target = make_user(email="proxy-target@example.com")
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Proxy Updated",
            "email": target.email,
        },
        headers={"X-Forwarded-For": "203.0.113.9"},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    assert str(log.ip_address) == "203.0.113.9"


def test_invalid_inbound_request_id_is_ignored(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="request-id-target@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "Request ID Updated",
            "email": target.email,
        },
        headers={"X-Request-ID": "not-a-uuid"},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    assert log.request_id != "not-a-uuid"
    assert len(log.request_id) == 32
    assert response.headers["X-Request-ID"] == log.request_id


def test_user_agent_is_truncated(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="ua-target@example.com")
    login(admin.email)

    client.post(
        f"/admin/users/{target.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{target.id}"),
            "full_name": "UA Updated",
            "email": target.email,
        },
        headers={"User-Agent": "A" * 600},
    )

    log = db.session.scalar(select(AuditLog))
    assert log is not None
    assert len(log.user_agent) == 512


def test_audit_update_is_rejected_by_database_trigger(
    app: Flask,
    make_user,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="trigger-update@example.com")
    log = _add_log(admin, target)

    with pytest.raises(SQLAlchemyError):
        db.session.execute(
            update(AuditLog).where(AuditLog.id == log.id).values(action=AUDIT_ACTION_ACTIVATED)
        )
        db.session.commit()
    db.session.rollback()

    db.session.refresh(log)
    assert log.action == AUDIT_ACTION_ROLE_CHANGED


def test_audit_delete_is_rejected_by_database_trigger(
    app: Flask,
    make_user,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="trigger-delete@example.com")
    log = _add_log(admin, target)

    with pytest.raises(SQLAlchemyError):
        db.session.delete(log)
        db.session.commit()
    db.session.rollback()

    assert db.session.get(AuditLog, log.id) is not None


def test_historical_identity_survives_user_deletion(
    app: Flask,
    make_user,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="deleted-target@example.com")
    log = _add_log(admin, target)
    log_id = log.id
    target_email = log.target_email

    db.session.delete(target)
    db.session.commit()

    persisted = db.session.get(AuditLog, log_id)
    assert persisted is not None
    assert persisted.target_user_id is None
    assert persisted.target_email == target_email
    assert persisted.target_email != ""


def test_historical_actor_identity_survives_actor_deletion(
    app: Flask,
    make_user,
) -> None:
    actor = _admin(make_user, email="deleted-actor@example.com")
    target = make_user(email="actor-history-target@example.com")
    log = _add_log(actor, target)
    log_id = log.id
    actor_email = log.actor_email

    db.session.delete(actor)
    db.session.commit()

    persisted = db.session.get(AuditLog, log_id)
    assert persisted is not None
    assert persisted.actor_id is None
    assert persisted.actor_email == actor_email
    assert persisted.actor_email != ""


def test_conflicting_profile_update_creates_no_audit_event(
    app: Flask,
    client: FlaskClient,
    make_user,
    login,
    csrf_token,
) -> None:
    admin = _admin(make_user)
    first = make_user(email="conflict-first@example.com")
    second = make_user(email="conflict-second@example.com")
    login(admin.email)

    response = client.post(
        f"/admin/users/{first.id}/profile",
        data={
            "csrf_token": csrf_token(f"/admin/users/{first.id}"),
            "full_name": first.full_name,
            "email": second.email,
        },
        follow_redirects=True,
    )

    db.session.refresh(first)
    assert first.email == "conflict-first@example.com"
    assert _audit_count() == 0
    assert "already exists" in response.get_data(as_text=True)


def test_audit_database_constraints(
    app: Flask,
    make_user,
) -> None:
    admin = _admin(make_user)
    target = make_user(email="constraint-target@example.com")

    invalid_action = AuditLog(
        actor_id=admin.id,
        actor_email=admin.email,
        target_user_id=target.id,
        target_email=target.email,
        action="user.deleted",
        before_data={"role": ROLE_CUSTOMER},
        after_data={"role": ROLE_CUSTOMER},
        ip_address="127.0.0.1",
        user_agent="",
        request_id=None,
    )
    db.session.add(invalid_action)
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    invalid_snapshot = AuditLog(
        actor_id=admin.id,
        actor_email=admin.email,
        target_user_id=target.id,
        target_email=target.email,
        action=AUDIT_ACTION_ROLE_CHANGED,
        before_data=["not", "an", "object"],
        after_data={"role": ROLE_CUSTOMER},
        ip_address="127.0.0.1",
        user_agent="",
        request_id=None,
    )
    db.session.add(invalid_snapshot)
    with pytest.raises(SQLAlchemyError):
        db.session.commit()
    db.session.rollback()

    invalid_ip = AuditLog(
        actor_id=admin.id,
        actor_email=admin.email,
        target_user_id=target.id,
        target_email=target.email,
        action=AUDIT_ACTION_ROLE_CHANGED,
        before_data={"role": ROLE_CUSTOMER},
        after_data={"role": ROLE_CUSTOMER},
        ip_address="not-an-ip",
        user_agent="",
        request_id=None,
    )
    db.session.add(invalid_ip)
    with pytest.raises(SQLAlchemyError):
        db.session.commit()
    db.session.rollback()
