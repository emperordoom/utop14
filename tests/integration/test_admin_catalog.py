"""Integration tests for admin category, product and variant management."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal

import pytest
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.catalog.seed import SeedSummary
from app.extensions import db
from app.models import Category, Order, OrderItem, Product, ProductImage, ProductVariant, User
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR

ADMIN_EMAIL = "catalog-admin@example.com"
CUSTOMER_EMAIL = "catalog-customer@example.com"


def _make_category(
    *,
    name: str = "T-shirts",
    slug: str = "t-shirts",
    position: int = 10,
    is_active: bool = True,
) -> Category:
    return Category(
        name=name,
        slug=slug,
        description=f"{name} description",
        icon="images/category-tees.svg",
        position=position,
        is_active=is_active,
    )


def _make_product(
    category: Category,
    *,
    name: str = "Void Tee",
    slug: str = "void-tee",
    price: str = "75.00",
    is_active: bool = True,
) -> Product:
    return Product(
        category=category,
        name=name,
        slug=slug,
        description=f"{name} description",
        price=Decimal(price),
        image_path="images/product-void-tee.svg",
        image_alt=f"{name} image",
        badge="New",
        is_active=is_active,
    )


def _make_variant(
    product: Product,
    *,
    size: str = "M",
    color: str = "Washed Black",
    sku: str = "U14-TEST-M",
    stock: int = 5,
    is_active: bool = True,
) -> ProductVariant:
    return ProductVariant(
        product=product,
        size=size,
        color=color,
        sku=sku,
        stock=stock,
        is_active=is_active,
    )


def _create_catalog(
    *,
    category_name: str = "Test Category",
    category_slug: str = "test-category",
    product_name: str = "Test Product",
    product_slug: str = "test-product",
    sku: str = "U14-TEST-M",
    stock: int = 5,
) -> tuple[Category, Product, ProductVariant]:
    category = _make_category(name=category_name, slug=category_slug)
    product = _make_product(category, name=product_name, slug=product_slug)
    variant = _make_variant(product, sku=sku, stock=stock)
    db.session.add_all([category, product, variant])
    db.session.commit()
    return category, product, variant


def _login_admin(
    make_user: Callable[..., User],
    login: Callable[..., object],
    *,
    email: str = ADMIN_EMAIL,
) -> User:
    user = make_user(email=email, role=ROLE_ADMIN)
    login(email)
    return user


def _product_form_data(
    category: Category,
    *,
    name: str = "Test Product",
    slug: str = "test-product",
    price: str = "75.00",
) -> dict[str, str]:
    return {
        "category_id": str(category.id),
        "name": name,
        "slug": slug,
        "description": "A catalog product used by the admin tests.",
        "price": price,
        "image_path": "images/product-void-tee.svg",
        "image_alt": f"{name} image",
        "badge": "Test",
    }


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_catalog_pages_are_forbidden_for_non_admins(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    role: str,
) -> None:
    email = f"catalog-pages-{role}@example.com"
    make_user(email=email, role=role)
    login(email)

    for path in (
        "/admin/categories",
        "/admin/categories/new",
        "/admin/products",
        "/admin/products/new",
        "/admin/inventory",
    ):
        assert client.get(path).status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/admin/categories",
        "/admin/categories/new",
        "/admin/products",
        "/admin/products/new",
        "/admin/inventory",
    ],
)
def test_catalog_pages_require_login(client: FlaskClient, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


@pytest.mark.parametrize("role", [ROLE_CUSTOMER, ROLE_OPERATOR])
def test_catalog_mutations_are_forbidden_for_non_admins(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    role: str,
) -> None:
    category, product, variant = _create_catalog()
    email = f"catalog-mutations-{role}@example.com"
    make_user(email=email, role=role)
    login(email)
    token = csrf_token("/auth/account")

    attempts = (
        (
            "/admin/categories/new",
            {
                "name": "Blocked Category",
                "slug": "blocked-category",
                "description": "",
                "icon": "images/category-tees.svg",
                "position": "0",
            },
        ),
        (f"/admin/categories/{category.id}/deactivate", {}),
        (f"/admin/products/{product.id}/deactivate", {}),
        (f"/admin/products/{product.id}/variants/{variant.id}/deactivate", {}),
        (f"/admin/inventory/{variant.id}/stock", {"stock": "99"}),
    )

    for path, data in attempts:
        response = client.post(path, data={"csrf_token": token, **data})
        assert response.status_code == 403

    db.session.expire_all()
    assert db.session.get(Category, category.id).is_active is True
    assert db.session.get(Product, product.id).is_active is True
    assert db.session.get(ProductVariant, variant.id).is_active is True
    assert db.session.get(ProductVariant, variant.id).stock == 5
    assert db.session.scalar(select(func.count()).select_from(Category)) == 1


def test_admin_category_crud_and_status_controls(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    _login_admin(make_user, login)

    empty_html = client.get("/admin/categories").get_data(as_text=True)
    assert "No categories yet" in empty_html

    token = csrf_token("/admin/categories/new")
    response = client.post(
        "/admin/categories/new",
        data={
            "csrf_token": token,
            "name": "Outerwear",
            "slug": "outerwear",
            "description": "Technical outer layers.",
            "icon": "images/category-tees.svg",
            "position": "5",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    created_html = response.get_data(as_text=True)
    assert "Outerwear" in created_html
    assert "created" in created_html.lower()

    category = db.session.scalar(select(Category).where(Category.slug == "outerwear"))
    assert category is not None
    category_id = category.id

    token = csrf_token(f"/admin/categories/{category_id}/edit")
    response = client.post(
        f"/admin/categories/{category_id}/edit",
        data={
            "csrf_token": token,
            "name": "Outerwear 014",
            "slug": "outerwear-014",
            "description": "Technical outer layers for the drop.",
            "icon": "images/category-tees.svg",
            "position": "6",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    updated_html = response.get_data(as_text=True)
    assert "Outerwear 014" in updated_html
    assert "updated" in updated_html.lower()

    db.session.expire_all()
    category = db.session.get(Category, category_id)
    assert category is not None
    assert category.name == "Outerwear 014"
    assert category.slug == "outerwear-014"
    assert category.position == 6

    token = csrf_token("/admin/categories")
    response = client.post(
        f"/admin/categories/{category_id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "deactivated" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    category = db.session.get(Category, category_id)
    assert category is not None
    assert category.is_active is False

    response = client.post(
        f"/admin/categories/{category_id}/activate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "activated" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    category = db.session.get(Category, category_id)
    assert category is not None
    assert category.is_active is True

    token = csrf_token("/admin/categories/new")
    duplicate = client.post(
        "/admin/categories/new",
        data={
            "csrf_token": token,
            "name": "Another Outerwear",
            "slug": "outerwear-014",
            "description": "",
            "icon": "images/category-tees.svg",
            "position": "7",
        },
        follow_redirects=True,
    )

    assert duplicate.status_code == 200
    assert "already exists" in duplicate.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(Category)) == 1

    invalid = client.post(
        "/admin/categories/new",
        data={
            "csrf_token": token,
            "name": "Invalid Slug",
            "slug": "Invalid Slug!",
            "description": "",
            "icon": "images/category-tees.svg",
            "position": "8",
        },
        follow_redirects=True,
    )

    assert invalid.status_code == 200
    assert "Slug must use lowercase" in invalid.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(Category)) == 1


def test_deactivating_category_hides_storefront_but_keeps_products(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category, product, _variant = _create_catalog(
        category_name="Outerwear",
        category_slug="outerwear",
        product_name="Test Jacket",
        product_slug="test-jacket",
        sku="U14-JKT-M",
    )

    assert "Test Jacket" in client.get("/shop").get_data(as_text=True)

    _login_admin(make_user, login)
    token = csrf_token("/admin/categories")
    response = client.post(
        f"/admin/categories/{category.id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "deactivated" in response.get_data(as_text=True).lower()
    assert "Test Jacket" not in client.get("/shop").get_data(as_text=True)
    assert client.get("/product/test-jacket").status_code == 404

    db.session.expire_all()
    refreshed_product = db.session.get(Product, product.id)
    refreshed_category = db.session.get(Category, category.id)
    assert refreshed_product is not None
    assert refreshed_product.is_active is True
    assert refreshed_category is not None
    assert refreshed_category.is_active is False


def test_admin_product_create_search_filter_edit_and_deactivate(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category = _make_category()
    db.session.add(category)
    db.session.commit()
    _login_admin(make_user, login)

    empty_html = client.get("/admin/products").get_data(as_text=True)
    assert "No matching products" in empty_html

    token = csrf_token("/admin/products/new")
    response = client.post(
        "/admin/products/new",
        data={
            "csrf_token": token,
            **_product_form_data(
                category,
                name="Test Hoodie",
                slug="test-hoodie",
                price="149.95",
            ),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    created_html = response.get_data(as_text=True)
    assert "Test Hoodie" in created_html
    assert "created" in created_html.lower()

    product = db.session.scalar(select(Product).where(Product.slug == "test-hoodie"))
    assert product is not None
    assert isinstance(product.price, Decimal)
    assert product.price == Decimal("149.95")
    product_id = product.id

    token = csrf_token(f"/admin/products/{product_id}/variants/new")
    variant_response = client.post(
        f"/admin/products/{product_id}/variants/new",
        data={
            "csrf_token": token,
            "size": "m",
            "color": "Washed Black",
            "sku": "u14-test-m",
            "stock": "4",
        },
        follow_redirects=True,
    )

    assert variant_response.status_code == 200
    assert "U14-TEST-M" in variant_response.get_data(as_text=True)

    name_html = client.get(
        "/admin/products",
        query_string={"q": "Test Hoodie"},
    ).get_data(as_text=True)
    assert "Test Hoodie" in name_html

    sku_html = client.get(
        "/admin/products",
        query_string={"q": "U14-TEST-M"},
    ).get_data(as_text=True)
    assert "Test Hoodie" in sku_html

    filtered_html = client.get(
        "/admin/products",
        query_string={"category": str(category.id), "status": "active"},
    ).get_data(as_text=True)
    assert "Test Hoodie" in filtered_html

    token = csrf_token(f"/admin/products/{product_id}/edit")
    response = client.post(
        f"/admin/products/{product_id}/edit",
        data={
            "csrf_token": token,
            **_product_form_data(
                category,
                name="Test Hoodie 2",
                slug="test-hoodie-2",
                price="99.50",
            ),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Test Hoodie 2" in response.get_data(as_text=True)

    db.session.expire_all()
    product = db.session.get(Product, product_id)
    assert product is not None
    assert product.name == "Test Hoodie 2"
    assert product.slug == "test-hoodie-2"
    assert product.price == Decimal("99.50")

    token = csrf_token("/admin/products")
    response = client.post(
        f"/admin/products/{product_id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "deactivated" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    product = db.session.get(Product, product_id)
    assert product is not None
    assert product.is_active is False
    assert client.get("/product/test-hoodie-2").status_code == 404

    inactive_html = client.get(
        "/admin/products",
        query_string={"status": "inactive"},
    ).get_data(as_text=True)
    assert "Test Hoodie 2" in inactive_html


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("price", "-1", "Price must be a non-negative"),
        ("slug", "Bad Slug!", "Slug must use lowercase"),
    ],
)
def test_admin_product_rejects_invalid_values(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    field: str,
    value: str,
    message: str,
) -> None:
    category = _make_category()
    db.session.add(category)
    db.session.commit()
    _login_admin(make_user, login)
    token = csrf_token("/admin/products/new")
    data = _product_form_data(category)
    data[field] = value

    response = client.post(
        "/admin/products/new",
        data={"csrf_token": token, **data},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert message in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(Product)) == 0


def test_admin_product_rejects_duplicate_slug(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category = _make_category()
    existing = _make_product(category, name="Existing Product", slug="existing-product")
    db.session.add_all([category, existing])
    db.session.commit()
    _login_admin(make_user, login)
    token = csrf_token("/admin/products/new")

    response = client.post(
        "/admin/products/new",
        data={
            "csrf_token": token,
            **_product_form_data(
                category,
                name="Duplicate Product",
                slug="existing-product",
            ),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "already exists" in response.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(Product)) == 1


def test_admin_product_rejects_unknown_category(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category = _make_category()
    db.session.add(category)
    db.session.commit()
    _login_admin(make_user, login)
    token = csrf_token("/admin/products/new")
    data = _product_form_data(category, name="Orphan Product", slug="orphan-product")
    data["category_id"] = "999999"

    response = client.post(
        "/admin/products/new",
        data={"csrf_token": token, **data},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "valid choice" in response.get_data(as_text=True).lower()
    assert db.session.scalar(select(func.count()).select_from(Product)) == 0


def test_admin_variant_crud_duplicate_sku_and_ownership(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category = _make_category()
    product = _make_product(category)
    db.session.add_all([category, product])
    db.session.commit()
    _login_admin(make_user, login)

    token = csrf_token(f"/admin/products/{product.id}/variants/new")
    response = client.post(
        f"/admin/products/{product.id}/variants/new",
        data={
            "csrf_token": token,
            "size": "m",
            "color": "Washed Black",
            "sku": "u14-test-m",
            "stock": "7",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "U14-TEST-M" in response.get_data(as_text=True)

    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == "U14-TEST-M"))
    assert variant is not None
    assert variant.size == "M"
    assert variant.stock == 7
    variant_id = variant.id

    token = csrf_token(f"/admin/products/{product.id}/variants/{variant_id}/edit")
    response = client.post(
        f"/admin/products/{product.id}/variants/{variant_id}/edit",
        data={
            "csrf_token": token,
            "size": "l",
            "color": "Bone",
            "sku": "u14-test-l",
            "stock": "11",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "U14-TEST-L" in response.get_data(as_text=True)

    db.session.expire_all()
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.size == "L"
    assert variant.color == "Bone"
    assert variant.sku == "U14-TEST-L"
    assert variant.stock == 11

    token = csrf_token(f"/admin/products/{product.id}/variants/new")
    duplicate = client.post(
        f"/admin/products/{product.id}/variants/new",
        data={
            "csrf_token": token,
            "size": "M",
            "color": "Bone",
            "sku": "U14-TEST-L",
            "stock": "3",
        },
        follow_redirects=True,
    )

    assert duplicate.status_code == 200
    assert "already exists" in duplicate.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(ProductVariant)) == 1

    negative = client.post(
        f"/admin/products/{product.id}/variants/new",
        data={
            "csrf_token": token,
            "size": "S",
            "color": "Bone",
            "sku": "U14-TEST-S",
            "stock": "-1",
        },
        follow_redirects=True,
    )

    assert negative.status_code == 200
    assert "Number must be between" in negative.get_data(as_text=True)
    assert db.session.scalar(select(func.count()).select_from(ProductVariant)) == 1

    token = csrf_token(f"/admin/products/{product.id}")
    response = client.post(
        f"/admin/products/{product.id}/variants/{variant_id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "deactivated" in response.get_data(as_text=True).lower()

    response = client.post(
        f"/admin/products/{product.id}/variants/{variant_id}/activate",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "activated" in response.get_data(as_text=True).lower()
    db.session.expire_all()
    variant = db.session.get(ProductVariant, variant_id)
    assert variant is not None
    assert variant.is_active is True

    other_category = _make_category(name="Other", slug="other", position=20)
    other_product = _make_product(
        other_category,
        name="Other Product",
        slug="other-product",
    )
    db.session.add_all([other_category, other_product])
    db.session.commit()

    assert (
        client.get(f"/admin/products/{other_product.id}/variants/{variant_id}/edit").status_code
        == 404
    )


def test_deactivated_product_and_variant_cannot_be_added_to_cart(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category, product, variant = _create_catalog(
        product_name="Hidden Tee",
        product_slug="hidden-tee",
        sku="U14-HIDDEN-M",
    )
    customer = make_user(email=CUSTOMER_EMAIL)
    make_user(email=ADMIN_EMAIL, role=ROLE_ADMIN)
    login(CUSTOMER_EMAIL)

    token = csrf_token("/cart")
    response = client.post(
        "/cart/add",
        data={
            "csrf_token": token,
            "variant_id": str(variant.id),
            "quantity": "1",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Hidden Tee" in response.get_data(as_text=True)

    _logout(client, csrf_token)
    login(ADMIN_EMAIL)
    token = csrf_token("/admin/products")
    response = client.post(
        f"/admin/products/{product.id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200

    _logout(client, csrf_token)
    login(CUSTOMER_EMAIL)
    response = client.post(
        "/cart/add",
        data={
            "csrf_token": csrf_token("/cart"),
            "variant_id": str(variant.id),
            "quantity": "1",
        },
        follow_redirects=True,
    )
    assert "not available" in response.get_data(as_text=True).lower()

    _logout(client, csrf_token)
    login(ADMIN_EMAIL)
    token = csrf_token("/admin/products")
    response = client.post(
        f"/admin/products/{product.id}/activate",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200

    response = client.post(
        f"/admin/products/{product.id}/variants/{variant.id}/deactivate",
        data={"csrf_token": token},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "deactivated" in response.get_data(as_text=True).lower()

    _logout(client, csrf_token)
    login(CUSTOMER_EMAIL)
    response = client.post(
        "/cart/add",
        data={
            "csrf_token": csrf_token("/cart"),
            "variant_id": str(variant.id),
            "quantity": "1",
        },
        follow_redirects=True,
    )
    assert "not available" in response.get_data(as_text=True).lower()

    db.session.expire_all()
    refreshed_product = db.session.get(Product, product.id)
    refreshed_variant = db.session.get(ProductVariant, variant.id)
    assert refreshed_product is not None
    assert refreshed_product.is_active is True
    assert refreshed_variant is not None
    assert refreshed_variant.is_active is False
    assert category.id == refreshed_product.category_id
    assert customer.id is not None


def test_admin_stock_adjustment_preserves_order_snapshots(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    make_order: Callable[..., Order],
    seeded_catalog: SeedSummary,
) -> None:
    customer = make_user(email="stock-customer@example.com")
    order = make_order(customer, sku="UT014-VT-WBK-M", quantity=2)
    item = db.session.scalar(select(OrderItem).where(OrderItem.order_id == order.id))
    variant = db.session.scalar(
        select(ProductVariant).where(ProductVariant.sku == "UT014-VT-WBK-M")
    )
    assert item is not None
    assert variant is not None

    snapshot = (
        item.product_name,
        item.sku,
        item.size,
        item.color,
        item.quantity,
        item.unit_price,
        item.line_total,
    )
    order_total = order.total
    previous_stock = variant.stock

    _login_admin(make_user, login)
    token = csrf_token("/admin/inventory")
    response = client.post(
        f"/admin/inventory/{variant.id}/stock",
        data={"csrf_token": token, "stock": "42"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    response_html = response.get_data(as_text=True)
    assert "updated from" in response_html
    assert "to 42" in response_html

    db.session.expire_all()
    refreshed_variant = db.session.get(ProductVariant, variant.id)
    refreshed_item = db.session.get(OrderItem, item.id)
    refreshed_order = db.session.get(Order, order.id)
    assert refreshed_variant is not None
    assert refreshed_variant.stock == 42
    assert previous_stock != 42
    assert refreshed_item is not None
    assert (
        refreshed_item.product_name,
        refreshed_item.sku,
        refreshed_item.size,
        refreshed_item.color,
        refreshed_item.quantity,
        refreshed_item.unit_price,
        refreshed_item.line_total,
    ) == snapshot
    assert refreshed_order is not None
    assert refreshed_order.total == order_total

    response = client.post(
        f"/admin/inventory/{variant.id}/stock",
        data={"csrf_token": token, "stock": "-1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Number must be between" in response.get_data(as_text=True)
    db.session.expire_all()
    assert db.session.get(ProductVariant, variant.id).stock == 42

    response = client.post(
        f"/admin/inventory/{variant.id}/stock",
        data={"stock": "0"},
    )
    assert response.status_code == 400
    db.session.expire_all()
    assert db.session.get(ProductVariant, variant.id).stock == 42


def test_admin_image_create_edit_delete_and_relation_validation(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    _category, product, _variant = _create_catalog(
        product_name="Image Product",
        product_slug="image-product",
        sku="U14-IMG-M",
    )
    _login_admin(make_user, login)

    token = csrf_token(f"/admin/products/{product.id}/images/new")
    response = client.post(
        f"/admin/products/{product.id}/images/new",
        data={
            "csrf_token": token,
            "image_path": "images/product-void-tee.svg",
            "alt_text": "Front view",
            "position": "0",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "images/product-void-tee.svg" in response.get_data(as_text=True)

    image = db.session.scalar(select(ProductImage).where(ProductImage.product_id == product.id))
    assert image is not None
    image_id = image.id

    token = csrf_token(f"/admin/products/{product.id}/images/{image_id}/edit")
    response = client.post(
        f"/admin/products/{product.id}/images/{image_id}/edit",
        data={
            "csrf_token": token,
            "image_path": "images/product-signal-hoodie.svg",
            "alt_text": "Back view",
            "position": "1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.expire_all()
    image = db.session.get(ProductImage, image_id)
    assert image is not None
    assert image.image_path == "images/product-signal-hoodie.svg"
    assert image.alt_text == "Back view"
    assert image.position == 1

    _other_category, other_product, _other_variant = _create_catalog(
        category_name="Other Category",
        category_slug="other-category",
        product_name="Other Image Product",
        product_slug="other-image-product",
        sku="U14-IMG-2",
    )
    other_image = ProductImage(
        product=other_product,
        image_path="images/product-orbit-cap.svg",
        alt_text="Other view",
        position=0,
    )
    db.session.add(other_image)
    db.session.commit()

    assert (
        client.get(f"/admin/products/{other_product.id}/images/{image_id}/edit").status_code == 404
    )

    token = csrf_token(f"/admin/products/{product.id}")
    response = client.post(
        f"/admin/products/{product.id}/images/{image_id}/delete",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Gallery image deleted" in response.get_data(as_text=True)
    db.session.expire_all()
    assert db.session.get(ProductImage, image_id) is None
    assert db.session.get(ProductImage, other_image.id) is not None
    refreshed_product = db.session.get(Product, product.id)
    assert refreshed_product is not None
    assert refreshed_product.image_path == "images/product-void-tee.svg"


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "images/../secret.webp",
        "javascript:alert(1)",
        "https://evil.test/product.webp",
        "/etc/passwd",
        "images\\product-void-tee.svg",
    ],
)
def test_admin_image_rejects_unsafe_paths(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    unsafe_path: str,
) -> None:
    _category, product, _variant = _create_catalog(
        product_name="Unsafe Image Product",
        product_slug="unsafe-image-product",
        sku="U14-UNSAFE-M",
    )
    _login_admin(make_user, login)
    token = csrf_token(f"/admin/products/{product.id}/images/new")

    response = client.post(
        f"/admin/products/{product.id}/images/new",
        data={
            "csrf_token": token,
            "image_path": unsafe_path,
            "alt_text": "Unsafe",
            "position": "0",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Image path" in response.get_data(as_text=True)
    assert (
        db.session.scalar(
            select(func.count())
            .select_from(ProductImage)
            .where(ProductImage.product_id == product.id)
        )
        == 0
    )


def test_admin_image_delete_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    _category, product, _variant = _create_catalog(
        product_name="CSRF Image Product",
        product_slug="csrf-image-product",
        sku="U14-CSRF-M",
    )
    image = ProductImage(
        product=product,
        image_path="images/product-void-tee.svg",
        alt_text="Front",
        position=0,
    )
    db.session.add(image)
    db.session.commit()
    _login_admin(make_user, login)

    response = client.post(
        f"/admin/products/{product.id}/images/{image.id}/delete",
        data={},
    )

    assert response.status_code == 400
    assert db.session.get(ProductImage, image.id) is not None


def test_staff_pages_include_shared_navigation_and_assets(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    _login_admin(make_user, login)

    for path in (
        "/admin",
        "/admin/categories",
        "/admin/products",
        "/admin/inventory",
        "/admin/orders",
    ):
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'class="admin-nav"' in html
        assert "/static/css/admin.css" in html
        assert "/static/js/admin.js" in html

    script = client.get("/static/js/admin.js")
    assert script.status_code == 200
    script_body = script.get_data(as_text=True)
    assert "data-confirm" in script_body
    assert "window.confirm" in script_body


def test_operator_navigation_hides_catalog_links(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    make_user(email="operator-nav@example.com", role=ROLE_OPERATOR)
    login("operator-nav@example.com")

    html = client.get("/ops").get_data(as_text=True)

    assert 'class="admin-nav"' in html
    assert "/admin/orders" in html
    assert "/admin/categories" not in html
    assert "/admin/products" not in html
    assert "/admin/inventory" not in html


def test_product_and_inventory_lists_are_paginated(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
) -> None:
    category = _make_category()
    db.session.add(category)
    db.session.flush()

    for index in range(21):
        product = _make_product(
            category,
            name=f"Page Product {index:02d}",
            slug=f"page-product-{index:02d}",
        )
        product.variants.append(
            _make_variant(
                product,
                size=f"S{index}",
                color="Black",
                sku=f"U14-PAGE-{index:02d}",
                stock=5,
            )
        )
        db.session.add(product)

    db.session.commit()
    _login_admin(make_user, login)

    product_first = client.get("/admin/products").get_data(as_text=True)
    product_second = client.get("/admin/products?page=2").get_data(as_text=True)
    assert product_first.count('class="admin-product-cell"') == 20
    assert product_second.count('class="admin-product-cell"') == 1

    inventory_first = client.get("/admin/inventory").get_data(as_text=True)
    inventory_second = client.get("/admin/inventory?page=2").get_data(as_text=True)
    assert inventory_first.count('class="admin-stock-form"') == 20
    assert inventory_second.count('class="admin-stock-form"') == 1
