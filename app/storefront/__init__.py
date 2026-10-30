"""Storefront blueprint and template helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from flask import Blueprint

from app.formatting import format_idr

storefront_bp = Blueprint("storefront", __name__)


@storefront_bp.app_template_filter("money")
def money(value: Decimal) -> str:
    """Render a price in the canonical Indonesian Rupiah format."""
    return format_idr(value)


@storefront_bp.app_context_processor
def inject_storefront_globals() -> dict[str, Any]:
    """Expose small, non-sensitive values required by the shared layout."""
    return {"current_year": datetime.now(UTC).year}


from app.storefront import routes  # noqa: E402, F401
