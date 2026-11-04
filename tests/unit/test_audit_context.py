"""Unit tests for request context, audit context and snapshot safety."""

from __future__ import annotations

from uuid import uuid4

import pytest
from flask import Flask, request

from app import create_app
from app.config import ConfigurationError
from app.models import User
from app.models.audit_log import AUDIT_ACTION_PROFILE_UPDATED
from app.request_context import (
    current_request_id,
    current_request_ip,
    init_request_context,
    normalize_ip_address,
    normalize_request_id,
    sanitize_user_agent,
)
from app.services.audit import (
    AuditContext,
    AuditValidationError,
    sanitize_snapshot,
    snapshot_active,
    snapshot_profile,
    snapshot_role,
)

# Keep app-creation tests independent of a developer's ambient HMAC key.
pytestmark = pytest.mark.usefixtures("no_ambient_security_event_hash_key")


def _metadata_app(hops: int) -> Flask:
    app = Flask(__name__)
    app.config["TRUSTED_PROXY_HOPS"] = hops
    init_request_context(app)

    @app.get("/metadata")
    def metadata():
        return {
            "request_id": current_request_id(),
            "ip": current_request_ip(),
            "user_agent": sanitize_user_agent(request.user_agent.string),
        }

    return app


def test_normalize_request_id_accepts_uuid_forms() -> None:
    expected = uuid4().hex
    assert normalize_request_id(expected) == expected
    dashed = str(uuid4())
    assert normalize_request_id(dashed) == dashed.replace("-", "")


@pytest.mark.parametrize("value", [None, 123, "", "not-a-uuid", "a" * 65])
def test_normalize_request_id_rejects_invalid_values(value: object) -> None:
    assert normalize_request_id(value) is None


def test_normalize_ip_address_supports_v4_and_v6() -> None:
    assert normalize_ip_address("203.0.113.9") == "203.0.113.9"
    assert normalize_ip_address("2001:0db8::1") == "2001:db8::1"


@pytest.mark.parametrize("value", [None, "", "not-an-ip", 123])
def test_normalize_ip_address_uses_safe_unknown(value: object) -> None:
    assert normalize_ip_address(value) == "0.0.0.0"


def test_sanitize_user_agent_removes_controls_and_truncates() -> None:
    cleaned = sanitize_user_agent("bad\x00value\r\n" + "a" * 600)

    assert "\x00" not in cleaned
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert len(cleaned) == 512


def test_server_generated_request_id_ignores_untrusted_inbound_header() -> None:
    app = _metadata_app(0)
    inbound = uuid4().hex

    response = app.test_client().get(
        "/metadata",
        headers={
            "X-Request-ID": inbound,
            "X-Forwarded-For": "203.0.113.9",
        },
    )

    payload = response.get_json()
    assert payload["request_id"] != inbound
    assert len(payload["request_id"]) == 32
    assert response.headers["X-Request-ID"] == payload["request_id"]
    assert payload["ip"] == "127.0.0.1"


def test_trusted_proxy_accepts_valid_request_id_and_client_ip() -> None:
    app = _metadata_app(1)
    inbound = uuid4()

    response = app.test_client().get(
        "/metadata",
        headers={
            "X-Request-ID": str(inbound),
            "X-Forwarded-For": "203.0.113.9",
        },
    )

    payload = response.get_json()
    assert payload["request_id"] == inbound.hex
    assert payload["ip"] == "203.0.113.9"
    assert response.headers["X-Request-ID"] == inbound.hex


def test_trusted_proxy_ignores_invalid_request_id() -> None:
    app = _metadata_app(1)

    response = app.test_client().get(
        "/metadata",
        headers={"X-Request-ID": "not-a-uuid"},
    )

    payload = response.get_json()
    assert payload["request_id"] != "not-a-uuid"
    assert len(payload["request_id"]) == 32


def test_audit_context_normalizes_metadata() -> None:
    request_id = uuid4()
    context = AuditContext(
        actor_id=7,
        actor_email="  ADMIN@Example.COM ",
        ip_address="2001:0db8::1",
        user_agent="agent\x00\r\n",
        request_id=str(request_id),
    )

    assert context.actor_email == "admin@example.com"
    assert context.ip_address == "2001:db8::1"
    assert context.user_agent == "agent"
    assert context.request_id == request_id.hex


@pytest.mark.parametrize(
    ("actor_id", "actor_email"),
    [(0, "admin@example.com"), (1, ""), (1, "a" * 256), ("1", "admin@example.com")],
)
def test_audit_context_rejects_invalid_actor(actor_id: object, actor_email: str) -> None:
    with pytest.raises(AuditValidationError):
        AuditContext(
            actor_id=actor_id,
            actor_email=actor_email,
            ip_address="127.0.0.1",
            user_agent="",
            request_id=None,
        )


def test_snapshots_use_explicit_allowlists() -> None:
    user = User(
        email="target@example.com",
        full_name="Target User",
        role="operator",
        is_active=True,
    )

    assert snapshot_profile(user) == {
        "full_name": "Target User",
        "email": "target@example.com",
    }
    assert snapshot_role(user) == {"role": "operator"}
    assert snapshot_active(user) == {"is_active": True}


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        "text",
        {"password": "secret"},
        {"password_hash": "hash"},
        {"session_id": "session"},
        {"csrf_token": "token"},
        {"nested": {"role": "admin"}},
    ],
)
def test_sanitize_snapshot_rejects_unsafe_values(value: object) -> None:
    with pytest.raises(AuditValidationError):
        sanitize_snapshot(value)


def test_sanitize_snapshot_accepts_flat_primitives() -> None:
    assert sanitize_snapshot(
        {
            "full_name": "Name",
            "email": "name@example.com",
            "is_active": True,
            "count": 3,
            "nothing": None,
        }
    ) == {
        "full_name": "Name",
        "email": "name@example.com",
        "is_active": True,
        "count": 3,
        "nothing": None,
    }


def test_audit_action_constant_is_importable() -> None:
    assert AUDIT_ACTION_PROFILE_UPDATED == "user.profile_updated"


def test_trusted_proxy_hops_defaults_to_zero() -> None:
    app = create_app("testing")

    assert app.config["TRUSTED_PROXY_HOPS"] == 0


@pytest.mark.parametrize("value", [-1, 6, "1", True, 1.5])
def test_invalid_trusted_proxy_hops_is_rejected(value: object) -> None:
    with pytest.raises(ConfigurationError, match="TRUSTED_PROXY_HOPS"):
        create_app("testing", {"TRUSTED_PROXY_HOPS": value})
