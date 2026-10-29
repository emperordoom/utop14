"""Customer order confirmation blueprint."""

from __future__ import annotations

from flask import Blueprint

orders_bp = Blueprint("orders", __name__)

from app.orders import routes  # noqa: E402, F401
