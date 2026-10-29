"""Shopping cart blueprint and routes."""

from __future__ import annotations

from flask import Blueprint

cart_bp = Blueprint("cart", __name__, url_prefix="/cart")

from app.cart import routes  # noqa: E402, F401
