"""Request identifiers, trusted-proxy handling and safe request metadata."""

from __future__ import annotations

import ipaddress
from uuid import UUID, uuid4

from flask import Flask, g, has_request_context, request
from werkzeug.middleware.proxy_fix import ProxyFix

MAX_REQUEST_ID_LENGTH = 64
MAX_USER_AGENT_LENGTH = 512
UNKNOWN_IP_ADDRESS = "0.0.0.0"


def normalize_request_id(value: object) -> str | None:
    """Return a canonical UUID hex request ID, or ``None`` for invalid input."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_REQUEST_ID_LENGTH:
        return None
    try:
        return UUID(candidate).hex
    except (ValueError, AttributeError):
        return None


def current_request_id() -> str | None:
    """Return the server-assigned request ID from the active request context."""
    if not has_request_context():
        return None
    value = getattr(g, "request_id", None)
    return value if isinstance(value, str) and value else None


def normalize_ip_address(value: object) -> str:
    """Return a canonical IPv4/IPv6 string, or a safe unknown sentinel."""
    if not isinstance(value, str):
        return UNKNOWN_IP_ADDRESS
    candidate = value.strip()
    if not candidate:
        return UNKNOWN_IP_ADDRESS
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return UNKNOWN_IP_ADDRESS


def current_request_ip() -> str:
    """Return the trusted client address after any configured ProxyFix step."""
    if not has_request_context():
        return UNKNOWN_IP_ADDRESS
    return normalize_ip_address(request.remote_addr)


def sanitize_user_agent(value: object) -> str:
    """Remove unsafe control characters and bound the stored user agent."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(
        character for character in value if character == "\t" or character.isprintable()
    )
    return cleaned.strip()[:MAX_USER_AGENT_LENGTH]


def current_user_agent() -> str:
    """Return the sanitized User-Agent for the active request."""
    if not has_request_context():
        return ""
    return sanitize_user_agent(request.user_agent.string)


def init_request_context(app: Flask) -> None:
    """Attach request IDs and optional trusted-proxy handling to the app."""
    hops = app.config.get("TRUSTED_PROXY_HOPS", 0)
    if type(hops) is int and hops > 0:
        # Only ``X-Forwarded-For`` is trusted, and only for the explicitly
        # configured number of proxy hops.  Host/proto headers are not used.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops)

    @app.before_request
    def _assign_request_id() -> None:
        inbound = request.headers.get("X-Request-ID")
        if hops > 0:
            g.request_id = normalize_request_id(inbound) or uuid4().hex
        else:
            # Forwarded or client-supplied IDs are ignored unless a trusted
            # proxy topology is explicitly configured.
            g.request_id = uuid4().hex

    @app.after_request
    def _expose_request_id(response):
        request_id = current_request_id()
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response
