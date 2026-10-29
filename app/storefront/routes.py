"""Public storefront routes."""

from __future__ import annotations

from flask import abort, render_template, request

from app.cart.forms import AddToCartForm
from app.services.catalog import (
    CatalogFilters,
    get_catalog_page,
    get_category_by_slug,
    get_product_by_slug,
    get_related_products,
    list_categories,
    list_products,
)
from app.storefront import storefront_bp
from app.storefront.content import FEATURED_COLLECTION


@storefront_bp.get("/")
def home() -> str:
    """Render the UTOP14 storefront homepage from the launch catalog."""
    return render_template(
        "storefront/home.html",
        products=list_products(limit=4),
        categories=list_categories(),
        collection=FEATURED_COLLECTION,
    )


@storefront_bp.get("/shop")
def shop() -> str:
    """Render the filterable catalog.

    Unknown or inactive category slugs return a branded 404 rather than an
    empty catalog, so stale links never masquerade as a valid collection.
    """
    filters = CatalogFilters.from_values(
        category=request.args.get("category"),
        size=request.args.get("size"),
        color=request.args.get("color"),
        q=request.args.get("q"),
    )
    active_category = None
    if filters.category is not None:
        active_category = get_category_by_slug(filters.category)
        if active_category is None:
            abort(404)

    page = get_catalog_page(filters)
    return render_template(
        "storefront/shop.html",
        page=page,
        active_category=active_category,
    )


@storefront_bp.get("/product/<slug>")
def product_detail(slug: str) -> str:
    """Render one active product with variants, gallery and related pieces."""
    product = get_product_by_slug(slug)
    if product is None:
        abort(404)

    return render_template(
        "storefront/product.html",
        product=product,
        related_products=get_related_products(product),
        add_to_cart_form=AddToCartForm(),
    )
