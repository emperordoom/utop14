"""Public routes for UTOP14."""

from __future__ import annotations

from flask import Response, jsonify

from app.main import main_bp


@main_bp.get("/health")
def health() -> tuple[Response, int]:
    """Return a minimal liveness response.

    The response intentionally contains no configuration, database, version or
    secret information.
    """
    return jsonify(status="ok"), 200
