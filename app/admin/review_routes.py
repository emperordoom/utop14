"""Admin-only product-review moderation routes."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user

from app.admin import admin_bp
from app.admin.forms import ActionForm, ReviewModerationForm
from app.auth.permissions import role_required
from app.models.product_review import (
    REVIEW_MAX_RATING,
    REVIEW_MIN_RATING,
    REVIEW_STATUS_HIDDEN,
    REVIEW_STATUS_PUBLISHED,
    REVIEW_STATUSES,
)
from app.models.user import ROLE_ADMIN
from app.services.reviews import (
    AdminReviewFilters,
    ReviewError,
    ReviewNotFound,
    ReviewValidationError,
    get_admin_review,
    list_admin_reviews,
    set_review_visibility,
)


@admin_bp.get("/admin/reviews")
@role_required(ROLE_ADMIN)
def review_list() -> ResponseReturnValue:
    """List reviews with status, rating, product and reviewer filters."""
    raw_rating = request.args.get("rating")
    filters = AdminReviewFilters.from_values(
        status=request.args.get("status"),
        rating=raw_rating,
        product=request.args.get("product"),
        q=request.args.get("q"),
    )
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = list_admin_reviews(filters, page=page)
    return render_template(
        "admin/review_list.html",
        pagination=pagination,
        filters=filters,
        query_params=filters.as_query_params(),
        statuses=REVIEW_STATUSES,
        ratings=range(REVIEW_MIN_RATING, REVIEW_MAX_RATING + 1),
    )


@admin_bp.get("/admin/reviews/<int:review_id>")
@role_required(ROLE_ADMIN)
def review_detail(review_id: int) -> ResponseReturnValue:
    """Show one review and its moderation controls without mutating state."""
    review = get_admin_review(review_id)
    if review is None:
        abort(404)

    return render_template(
        "admin/review_detail.html",
        review=review,
        hide_form=ReviewModerationForm(),
        publish_form=ActionForm(),
    )


@admin_bp.post("/admin/reviews/<int:review_id>/hide")
@role_required(ROLE_ADMIN)
def review_hide(review_id: int) -> ResponseReturnValue:
    """Hide one review with a mandatory moderation reason."""
    form = ReviewModerationForm()
    if not form.validate_on_submit():
        flash("A valid moderation reason is required.", "error")
        return redirect(url_for("admin.review_detail", review_id=review_id))

    try:
        result = set_review_visibility(
            review_id,
            current_user.id,
            REVIEW_STATUS_HIDDEN,
            reason=form.reason.data,
        )
    except ReviewNotFound:
        abort(404)
    except ReviewValidationError as exc:
        flash(str(exc), "error")
    except ReviewError:
        flash("The review could not be updated. Please try again.", "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.review_detail", review_id=review_id))


@admin_bp.post("/admin/reviews/<int:review_id>/publish")
@role_required(ROLE_ADMIN)
def review_publish(review_id: int) -> ResponseReturnValue:
    """Publish one previously hidden review."""
    form = ActionForm()
    if not form.validate_on_submit():
        flash("The review could not be published.", "error")
        return redirect(url_for("admin.review_detail", review_id=review_id))

    try:
        result = set_review_visibility(
            review_id,
            current_user.id,
            REVIEW_STATUS_PUBLISHED,
        )
    except ReviewNotFound:
        abort(404)
    except ReviewValidationError as exc:
        flash(str(exc), "error")
    except ReviewError:
        flash("The review could not be updated. Please try again.", "error")
    else:
        flash(result.message, result.category)

    return redirect(url_for("admin.review_detail", review_id=review_id))
