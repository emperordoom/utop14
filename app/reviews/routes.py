"""Customer review submission, editing and history routes."""

from __future__ import annotations

from flask import abort, flash, redirect, render_template, request, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required

from app.reviews import reviews_bp
from app.reviews.forms import ReviewEditForm, ReviewForm
from app.services.catalog import get_product_by_slug
from app.services.reviews import (
    ReviewConflictError,
    ReviewEligibilityError,
    ReviewError,
    ReviewNotFound,
    ReviewValidationError,
    create_product_review,
    get_user_review,
    get_user_reviews,
    update_product_review,
)


def _first_error(form: ReviewForm | ReviewEditForm) -> str:
    for errors in form.errors.values():
        if errors:
            return errors[0]
    return "Please check the review form and try again."


def _parse_order_item_id(raw: object) -> int | None:
    """Parse an optional hidden purchase reference without trusting it."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ReviewValidationError("The selected purchase is invalid.")
    cleaned = raw.strip()
    if not cleaned:
        return None
    if not cleaned.isdigit():
        raise ReviewValidationError("The selected purchase is invalid.")
    return int(cleaned)


@reviews_bp.post("/products/<slug>/reviews")
@login_required
def create(slug: str) -> ResponseReturnValue:
    """Publish one review for the signed-in customer's eligible purchase."""
    product = get_product_by_slug(slug)
    if product is None:
        abort(404)

    form = ReviewForm()
    if not form.validate_on_submit():
        flash(_first_error(form), "error")
        return redirect(url_for("storefront.product_detail", slug=slug, _anchor="reviews"))

    try:
        order_item_id = _parse_order_item_id(form.order_item_id.data)
        create_product_review(
            current_user.id,
            product.id,
            rating=form.rating.data,
            comment=form.comment.data,
            order_item_id=order_item_id,
        )
    except ReviewValidationError as exc:
        flash(str(exc), "error")
    except ReviewEligibilityError as exc:
        flash(str(exc), "error")
    except ReviewConflictError as exc:
        flash(str(exc), "error")
    except ReviewError:
        flash("Your review could not be saved. Please try again.", "error")
    else:
        flash("Review published. Thanks for the signal.", "success")

    return redirect(url_for("storefront.product_detail", slug=slug, _anchor="reviews"))


@reviews_bp.route("/reviews/<int:review_id>/edit", methods=["GET", "POST"])
@login_required
def edit(review_id: int) -> ResponseReturnValue:
    """Edit only the signed-in owner's rating and comment."""
    review = get_user_review(current_user.id, review_id)
    if review is None:
        abort(404)

    form = ReviewEditForm(obj=review)
    if form.validate_on_submit():
        try:
            update_product_review(
                current_user.id,
                review_id,
                rating=form.rating.data,
                comment=form.comment.data,
            )
        except ReviewNotFound:
            abort(404)
        except ReviewValidationError as exc:
            flash(str(exc), "error")
        except ReviewError:
            flash("Your review could not be updated. Please try again.", "error")
        else:
            flash("Review updated.", "success")
            return redirect(url_for("reviews.history"))

    return render_template("reviews/edit.html", form=form, review=review)


@reviews_bp.get("/account/reviews")
@login_required
def history() -> ResponseReturnValue:
    """Show the signed-in customer's own review history, including hidden rows."""
    page = max(1, request.args.get("page", 1, type=int) or 1)
    pagination = get_user_reviews(current_user.id, page=page)
    return render_template("reviews/history.html", pagination=pagination)
