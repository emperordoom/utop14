"""Public storefront routes."""

from __future__ import annotations

from flask import render_template

from app.storefront import storefront_bp
from app.storefront.content import CATEGORIES, FEATURED_COLLECTION, PRODUCTS


@storefront_bp.get("/")
def home() -> str:
    """Render the UTOP14 storefront homepage."""
    return render_template(
        "storefront/home.html",
        products=PRODUCTS,
        categories=CATEGORIES,
        collection=FEATURED_COLLECTION,
    )
