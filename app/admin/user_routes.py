"""Admin-only account directory and management routes."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user

from app.admin import admin_bp
from app.admin.forms import ActionForm, AdminUserProfileForm, AdminUserRoleForm
from app.auth.permissions import role_required
from app.models.user import ROLE_ADMIN, ROLES
from app.services.audit import build_audit_context
from app.services.user_admin import (
    AdminUserFilters,
    UserAdminConflictError,
    UserAdminError,
    UserAdminNotFound,
    UserAdminStateError,
    UserAdminValidationError,
    count_active_admins,
    get_admin_user,
    list_admin_users,
    set_user_active,
    set_user_role,
    update_user_by_admin,
)


def _first_error(form: AdminUserProfileForm | AdminUserRoleForm) -> str:
    for errors in form.errors.values():
        if errors:
            return errors[0]
    return "Please check the account form and try again."


@admin_bp.get("/admin/users")
@role_required(ROLE_ADMIN)
def user_list() -> ResponseReturnValue:
    """List accounts with search, role, status and pagination controls."""
    filters = AdminUserFilters.from_values(
        q=request.args.get("q"),
        role=request.args.get("role"),
        status=request.args.get("status"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_admin_users(filters, page=page)
    return render_template(
        "admin/user_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        roles=ROLES,
        statuses=(("active", "Active"), ("inactive", "Inactive")),
    )


@admin_bp.get("/admin/users/<int:user_id>")
@role_required(ROLE_ADMIN)
def user_detail(user_id: int) -> ResponseReturnValue:
    """Render one account with profile, role and status controls."""
    user = get_admin_user(user_id)
    if user is None:
        abort(404)

    active_admins = count_active_admins()
    is_self = user.id == current_user.id
    return render_template(
        "admin/user_detail.html",
        user=user,
        profile_form=AdminUserProfileForm(obj=user),
        role_form=AdminUserRoleForm(obj=user),
        status_form=ActionForm(),
        is_self=is_self,
        active_admin_count=active_admins,
        can_change_role=not (is_self and user.is_admin),
        can_deactivate=(
            user.is_active
            and not (is_self and user.is_admin)
            and (not user.is_admin or active_admins > 1)
        ),
    )


@admin_bp.post("/admin/users/<int:user_id>/profile")
@role_required(ROLE_ADMIN)
def user_profile_update(user_id: int) -> ResponseReturnValue:
    """Update only the account's full name and email."""
    form = AdminUserProfileForm()
    if not form.validate_on_submit():
        flash(_first_error(form), "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    try:
        result = update_user_by_admin(
            user_id,
            full_name=form.full_name.data,
            email=form.email.data,
            audit_context=build_audit_context(
                actor_id=current_user.id,
                actor_email=current_user.email,
            ),
        )
    except UserAdminNotFound:
        abort(404)
    except UserAdminConflictError as exc:
        flash(str(exc), "error")
    except UserAdminValidationError as exc:
        flash(str(exc), "error")
    except UserAdminError:
        flash("Account details could not be saved. Please try again.", "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.user_detail", user_id=user_id))


@admin_bp.post("/admin/users/<int:user_id>/role")
@role_required(ROLE_ADMIN)
def user_role_update(user_id: int) -> ResponseReturnValue:
    """Change one account role with server-side policy enforcement."""
    form = AdminUserRoleForm()
    if not form.validate_on_submit():
        flash("Choose a valid role.", "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    try:
        result = set_user_role(
            current_user.id,
            user_id,
            role=form.role.data,
            audit_context=build_audit_context(
                actor_id=current_user.id,
                actor_email=current_user.email,
            ),
        )
    except UserAdminNotFound:
        abort(404)
    except (UserAdminStateError, UserAdminValidationError) as exc:
        flash(str(exc), "error")
    except UserAdminError:
        flash("Account role could not be updated. Please try again.", "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.user_detail", user_id=user_id))


def _change_status(user_id: int, *, is_active: bool) -> ResponseReturnValue:
    form = ActionForm()
    if not form.validate_on_submit():
        flash("The account status could not be changed.", "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    try:
        result = set_user_active(
            current_user.id,
            user_id,
            is_active=is_active,
            audit_context=build_audit_context(
                actor_id=current_user.id,
                actor_email=current_user.email,
            ),
        )
    except UserAdminNotFound:
        abort(404)
    except UserAdminStateError as exc:
        flash(str(exc), "error")
    except UserAdminError:
        flash("Account status could not be updated. Please try again.", "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.user_detail", user_id=user_id))


@admin_bp.post("/admin/users/<int:user_id>/activate")
@role_required(ROLE_ADMIN)
def user_activate(user_id: int) -> ResponseReturnValue:
    """Reactivate one account."""
    return _change_status(user_id, is_active=True)


@admin_bp.post("/admin/users/<int:user_id>/deactivate")
@role_required(ROLE_ADMIN)
def user_deactivate(user_id: int) -> ResponseReturnValue:
    """Deactivate one account without deleting it."""
    return _change_status(user_id, is_active=False)
