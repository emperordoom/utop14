"""Checkout blueprint and routes."""

from __future__ import annotations

from flask import Blueprint

checkout_bp = Blueprint("checkout", __name__, url_prefix="/checkout")

from app.checkout import routes  # noqa: E402, F401
