"""Storefront blueprint and template helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from flask import Blueprint

from app.formatting import format_idr, format_payment_amount
from app.services.checkout import FREE_SHIPPING_THRESHOLD_IDR, SHIPPING_FLAT_IDR

storefront_bp = Blueprint("storefront", __name__)


@storefront_bp.app_template_filter("money")
def money(value: Decimal) -> str:
    """Render a price in the canonical Indonesian Rupiah format."""
    return format_idr(value)


@storefront_bp.app_template_filter("payment_money")
def payment_money(payment: Any) -> str:
    """Render a payment amount in IDR, or fail closed for unsupported currencies."""
    return format_payment_amount(payment.amount, getattr(payment, "currency", None))


@storefront_bp.app_context_processor
def inject_storefront_globals() -> dict[str, Any]:
    """Expose small, non-sensitive values required by the shared layout."""
    return {
        "current_year": datetime.now(UTC).year,
        "shipping_flat_idr": SHIPPING_FLAT_IDR,
        "free_shipping_threshold_idr": FREE_SHIPPING_THRESHOLD_IDR,
    }


from app.storefront import routes  # noqa: E402, F401
