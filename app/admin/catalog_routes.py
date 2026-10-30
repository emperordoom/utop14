"""Admin-only catalog, variant, image and inventory routes.

Every view in this module requires the exact admin role.  Operators can manage
orders but cannot read or mutate catalog administration screens.
"""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_wtf import FlaskForm

from app.admin import admin_bp
from app.admin.forms import (
    ActionForm,
    CategoryForm,
    ImageForm,
    ProductForm,
    StockForm,
    VariantForm,
)
from app.auth.permissions import role_required
from app.models import ProductVariant
from app.models.user import ROLE_ADMIN
from app.services.catalog_admin import (
    CatalogAdminError,
    CatalogNotFound,
    InventoryFilters,
    ProductAdminFilters,
    adjust_stock,
    create_category,
    create_product,
    create_product_image,
    create_variant,
    delete_product_image,
    get_category_admin,
    get_product_admin,
    get_product_image,
    get_variant_admin,
    list_categories_admin,
    list_category_choices,
    list_inventory_admin,
    list_products_admin,
    set_category_active,
    set_product_active,
    set_variant_active,
    update_category,
    update_product,
    update_product_image,
    update_variant,
)


def _flash_first_error(form: FlaskForm, fallback: str) -> None:
    """Flash the first form error, or a fallback message."""
    for errors in form.errors.values():
        if errors:
            flash(errors[0], "error")
            return
    flash(fallback, "error")


def _flash_catalog_error(exc: CatalogAdminError) -> None:
    flash(str(exc), "error")


@admin_bp.get("/admin/categories")
@role_required(ROLE_ADMIN)
def category_list() -> ResponseReturnValue:
    """List every category with product counts and status controls."""
    return render_template(
        "admin/category_list.html",
        summaries=list_categories_admin(),
    )


@admin_bp.route("/admin/categories/new", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def category_create() -> ResponseReturnValue:
    """Create a category."""
    form = CategoryForm()
    if form.validate_on_submit():
        try:
            category = create_category(form)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Category “{category.name}” created.", "success")
            return redirect(url_for("admin.category_list"))
    elif request.method == "POST":
        _flash_first_error(form, "Check the category fields and try again.")

    return render_template(
        "admin/category_form.html",
        form=form,
        category=None,
        page_title="New category",
    )


@admin_bp.route("/admin/categories/<int:category_id>/edit", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def category_edit(category_id: int) -> ResponseReturnValue:
    """Edit a category and review its related products."""
    category = get_category_admin(category_id)
    if category is None:
        abort(404)

    form = CategoryForm(obj=category) if request.method == "GET" else CategoryForm()
    if form.validate_on_submit():
        try:
            updated = update_category(category_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Category “{updated.name}” updated.", "success")
            return redirect(url_for("admin.category_list"))
    elif request.method == "POST":
        _flash_first_error(form, "Check the category fields and try again.")

    return render_template(
        "admin/category_form.html",
        form=form,
        category=category,
        page_title=f"Edit {category.name}",
    )


@admin_bp.post("/admin/categories/<int:category_id>/activate")
@role_required(ROLE_ADMIN)
def category_activate(category_id: int) -> ResponseReturnValue:
    """Activate a category."""
    return _set_category_status(category_id, True)


@admin_bp.post("/admin/categories/<int:category_id>/deactivate")
@role_required(ROLE_ADMIN)
def category_deactivate(category_id: int) -> ResponseReturnValue:
    """Deactivate a category without deleting its products."""
    return _set_category_status(category_id, False)


def _set_category_status(category_id: int, is_active: bool) -> ResponseReturnValue:
    form = ActionForm()
    if not form.validate_on_submit():
        _flash_first_error(form, "The category status could not be updated.")
        return redirect(url_for("admin.category_list"))

    try:
        category = set_category_active(category_id, is_active)
    except CatalogNotFound:
        abort(404)
    except CatalogAdminError as exc:
        _flash_catalog_error(exc)
    else:
        state = "activated" if is_active else "deactivated"
        flash(f"Category “{category.name}” {state}.", "success")
    return redirect(url_for("admin.category_list"))


@admin_bp.get("/admin/products")
@role_required(ROLE_ADMIN)
def product_list() -> ResponseReturnValue:
    """List and filter products."""
    filters = ProductAdminFilters.from_values(
        q=request.args.get("q"),
        category_id=request.args.get("category"),
        status=request.args.get("status"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_products_admin(filters, page=page)
    return render_template(
        "admin/product_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        categories=list_category_choices(),
    )


@admin_bp.route("/admin/products/new", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def product_create() -> ResponseReturnValue:
    """Create a product."""
    form = ProductForm()
    form.category_id.choices = list_category_choices()
    if form.validate_on_submit():
        try:
            product = create_product(form)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Product “{product.name}” created.", "success")
            return redirect(url_for("admin.product_detail", product_id=product.id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the product fields and try again.")

    return render_template(
        "admin/product_form.html",
        form=form,
        product=None,
        page_title="New product",
    )


@admin_bp.get("/admin/products/<int:product_id>")
@role_required(ROLE_ADMIN)
def product_detail(product_id: int) -> ResponseReturnValue:
    """Show one product with its variants and gallery images."""
    product = get_product_admin(product_id)
    if product is None:
        abort(404)

    return render_template(
        "admin/product_detail.html",
        product=product,
    )


@admin_bp.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def product_edit(product_id: int) -> ResponseReturnValue:
    """Edit a product."""
    product = get_product_admin(product_id)
    if product is None:
        abort(404)

    form = ProductForm(obj=product) if request.method == "GET" else ProductForm()
    form.category_id.choices = list_category_choices()
    if form.validate_on_submit():
        try:
            updated = update_product(product_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Product “{updated.name}” updated.", "success")
            return redirect(url_for("admin.product_detail", product_id=product_id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the product fields and try again.")

    return render_template(
        "admin/product_form.html",
        form=form,
        product=product,
        page_title=f"Edit {product.name}",
    )


@admin_bp.post("/admin/products/<int:product_id>/activate")
@role_required(ROLE_ADMIN)
def product_activate(product_id: int) -> ResponseReturnValue:
    """Activate a product."""
    return _set_product_status(product_id, True)


@admin_bp.post("/admin/products/<int:product_id>/deactivate")
@role_required(ROLE_ADMIN)
def product_deactivate(product_id: int) -> ResponseReturnValue:
    """Deactivate a product and hide it from the storefront."""
    return _set_product_status(product_id, False)


def _set_product_status(product_id: int, is_active: bool) -> ResponseReturnValue:
    form = ActionForm()
    if not form.validate_on_submit():
        _flash_first_error(form, "The product status could not be updated.")
        return redirect(url_for("admin.product_list"))

    try:
        product = set_product_active(product_id, is_active)
    except CatalogNotFound:
        abort(404)
    except CatalogAdminError as exc:
        _flash_catalog_error(exc)
    else:
        state = "activated" if is_active else "deactivated"
        flash(f"Product “{product.name}” {state}.", "success")
    return redirect(url_for("admin.product_list"))


@admin_bp.route("/admin/products/<int:product_id>/variants/new", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def variant_create(product_id: int) -> ResponseReturnValue:
    """Create a variant for one product."""
    product = get_product_admin(product_id)
    if product is None:
        abort(404)

    form = VariantForm()
    if request.method == "GET":
        form.stock.data = 0
    if form.validate_on_submit():
        try:
            variant = create_variant(product_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Variant {variant.sku} created.", "success")
            return redirect(url_for("admin.product_detail", product_id=product_id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the variant fields and try again.")

    return render_template(
        "admin/variant_form.html",
        form=form,
        product=product,
        variant=None,
        page_title=f"New variant — {product.name}",
    )


@admin_bp.route(
    "/admin/products/<int:product_id>/variants/<int:variant_id>/edit",
    methods=["GET", "POST"],
)
@role_required(ROLE_ADMIN)
def variant_edit(product_id: int, variant_id: int) -> ResponseReturnValue:
    """Edit a variant that belongs to the product in the URL."""
    product, variant = _owned_variant(product_id, variant_id)
    form = VariantForm(obj=variant) if request.method == "GET" else VariantForm()
    if form.validate_on_submit():
        try:
            updated = update_variant(variant_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Variant {updated.sku} updated.", "success")
            return redirect(url_for("admin.product_detail", product_id=product_id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the variant fields and try again.")

    return render_template(
        "admin/variant_form.html",
        form=form,
        product=product,
        variant=variant,
        page_title=f"Edit {variant.sku}",
    )


@admin_bp.post("/admin/products/<int:product_id>/variants/<int:variant_id>/activate")
@role_required(ROLE_ADMIN)
def variant_activate(product_id: int, variant_id: int) -> ResponseReturnValue:
    """Activate a variant."""
    return _set_variant_status(product_id, variant_id, True)


@admin_bp.post("/admin/products/<int:product_id>/variants/<int:variant_id>/deactivate")
@role_required(ROLE_ADMIN)
def variant_deactivate(product_id: int, variant_id: int) -> ResponseReturnValue:
    """Deactivate a variant so it cannot be purchased."""
    return _set_variant_status(product_id, variant_id, False)


def _owned_variant(product_id: int, variant_id: int) -> tuple[object, ProductVariant]:
    product = get_product_admin(product_id)
    if product is None:
        abort(404)
    variant = get_variant_admin(variant_id)
    if variant is None or variant.product_id != product.id:
        abort(404)
    return product, variant


def _set_variant_status(
    product_id: int,
    variant_id: int,
    is_active: bool,
) -> ResponseReturnValue:
    _owned_variant(product_id, variant_id)
    form = ActionForm()
    if not form.validate_on_submit():
        _flash_first_error(form, "The variant status could not be updated.")
        return redirect(url_for("admin.product_detail", product_id=product_id))

    try:
        variant = set_variant_active(variant_id, is_active)
    except CatalogNotFound:
        abort(404)
    except CatalogAdminError as exc:
        _flash_catalog_error(exc)
    else:
        state = "activated" if is_active else "deactivated"
        flash(f"Variant {variant.sku} {state}.", "success")
    return redirect(url_for("admin.product_detail", product_id=product_id))


@admin_bp.route("/admin/products/<int:product_id>/images/new", methods=["GET", "POST"])
@role_required(ROLE_ADMIN)
def image_create(product_id: int) -> ResponseReturnValue:
    """Add a gallery image path to one product."""
    product = get_product_admin(product_id)
    if product is None:
        abort(404)

    form = ImageForm()
    if request.method == "GET":
        form.position.data = len(product.images)
    if form.validate_on_submit():
        try:
            image = create_product_image(product_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Gallery image at position {image.position} added.", "success")
            return redirect(url_for("admin.product_detail", product_id=product_id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the image fields and try again.")

    return render_template(
        "admin/image_form.html",
        form=form,
        product=product,
        image=None,
        page_title=f"New gallery image — {product.name}",
    )


@admin_bp.route(
    "/admin/products/<int:product_id>/images/<int:image_id>/edit",
    methods=["GET", "POST"],
)
@role_required(ROLE_ADMIN)
def image_edit(product_id: int, image_id: int) -> ResponseReturnValue:
    """Edit a gallery image that belongs to the product in the URL."""
    product = get_product_admin(product_id)
    if product is None:
        abort(404)
    image = get_product_image(product_id, image_id)
    if image is None:
        abort(404)

    form = ImageForm(obj=image) if request.method == "GET" else ImageForm()
    if form.validate_on_submit():
        try:
            updated = update_product_image(product_id, image_id, form)
        except CatalogNotFound:
            abort(404)
        except CatalogAdminError as exc:
            _flash_catalog_error(exc)
        else:
            flash(f"Gallery image at position {updated.position} updated.", "success")
            return redirect(url_for("admin.product_detail", product_id=product_id))
    elif request.method == "POST":
        _flash_first_error(form, "Check the image fields and try again.")

    return render_template(
        "admin/image_form.html",
        form=form,
        product=product,
        image=image,
        page_title=f"Edit gallery image — {product.name}",
    )


@admin_bp.post("/admin/products/<int:product_id>/images/<int:image_id>/delete")
@role_required(ROLE_ADMIN)
def image_delete(product_id: int, image_id: int) -> ResponseReturnValue:
    """Delete a gallery image without touching the product card image."""
    form = ActionForm()
    if not form.validate_on_submit():
        _flash_first_error(form, "The gallery image could not be deleted.")
        return redirect(url_for("admin.product_detail", product_id=product_id))

    try:
        delete_product_image(product_id, image_id)
    except CatalogNotFound:
        abort(404)
    except CatalogAdminError as exc:
        _flash_catalog_error(exc)
    else:
        flash("Gallery image deleted. The product card image is unchanged.", "success")
    return redirect(url_for("admin.product_detail", product_id=product_id))


@admin_bp.get("/admin/inventory")
@role_required(ROLE_ADMIN)
def inventory_list() -> ResponseReturnValue:
    """List variants with filters and inline absolute stock controls."""
    filters = InventoryFilters.from_values(
        q=request.args.get("q"),
        stock_status=request.args.get("stock"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_inventory_admin(filters, page=page)
    return render_template(
        "admin/inventory_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
    )


@admin_bp.post("/admin/inventory/<int:variant_id>/stock")
@role_required(ROLE_ADMIN)
def inventory_adjust(variant_id: int) -> ResponseReturnValue:
    """Set an absolute stock value under a database row lock."""
    form = StockForm()
    if not form.validate_on_submit():
        _flash_first_error(form, "Stock must be a whole number between 0 and 1,000,000.")
        return redirect(url_for("admin.inventory_list"))

    try:
        change = adjust_stock(variant_id, form.stock.data)
    except CatalogNotFound:
        abort(404)
    except CatalogAdminError as exc:
        _flash_catalog_error(exc)
    else:
        flash(
            f"Stock for {change.variant.sku} updated from "
            f"{change.previous_stock} to {change.new_stock}.",
            "success",
        )
    return redirect(url_for("admin.inventory_list"))
