"""Unit tests for catalog-admin query-string normalization."""

from __future__ import annotations

from app.services.catalog_admin import InventoryFilters, ProductAdminFilters


def test_product_admin_filters_normalize_untrusted_values() -> None:
    filters = ProductAdminFilters.from_values(
        q="  void tee  ",
        category_id=" 12 ",
        status=" ACTIVE ",
    )

    assert filters.query == "void tee"
    assert filters.category_id == 12
    assert filters.status == "active"
    assert filters.active_count == 3
    assert filters.as_query_params() == {
        "q": "void tee",
        "category": "12",
        "status": "active",
    }


def test_product_admin_filters_drop_blank_and_unknown_values() -> None:
    filters = ProductAdminFilters.from_values(
        q="   ",
        category_id="not-a-number",
        status="deleted",
    )

    assert filters.query is None
    assert filters.category_id is None
    assert filters.status is None
    assert filters.active_count == 0
    assert filters.as_query_params() == {}


def test_inventory_filters_normalize_untrusted_values() -> None:
    filters = InventoryFilters.from_values(q="  black ", stock_status=" LOW ")

    assert filters.query == "black"
    assert filters.stock_status == "low"
    assert filters.active_count == 2
    assert filters.as_query_params() == {"q": "black", "stock": "low"}


def test_inventory_filters_drop_blank_and_unknown_values() -> None:
    filters = InventoryFilters.from_values(q="", stock_status="plenty")

    assert filters.query is None
    assert filters.stock_status is None
    assert filters.active_count == 0
    assert filters.as_query_params() == {}
