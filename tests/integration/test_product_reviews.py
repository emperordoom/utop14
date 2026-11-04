"""Integration tests for verified-purchase product reviews."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Order, OrderItem, Product, ProductReview, User
from app.models.product_review import (
    REVIEW_STATUS_HIDDEN,
    REVIEW_STATUS_PUBLISHED,
)
from app.models.user import ROLE_ADMIN
from app.services.reviews import (
    ReviewConflictError,
    ReviewEligibilityError,
    ReviewNotFound,
    ReviewValidationError,
    create_product_review,
    get_review_eligibility,
    get_review_summary,
    get_user_reviews,
    set_review_visibility,
    update_product_review,
)

VOID_TEE_SKU = "UT014-VT-WBK-M"
HOODIE_SKU = "UT014-SH-FCH-M"


def _delivered_paid_order(user: User, make_order, *, sku: str = VOID_TEE_SKU) -> Order:
    return make_order(user, sku=sku, status="delivered", payment_status="paid")


def _product_id(order: Order) -> int:
    product_id = order.items[0].product_id
    assert product_id is not None
    return product_id


def _create_review(
    user: User,
    order: Order,
    *,
    rating: int = 5,
    comment: str = "Built to last.",
) -> ProductReview:
    return create_product_review(
        user.id,
        _product_id(order),
        rating=rating,
        comment=comment,
    )


def _html(response) -> str:
    return response.get_data(as_text=True)


def test_eligible_customer_can_submit_review(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="buyer@example.com", full_name="Ada Buyer")
    order = _delivered_paid_order(user, make_order)
    login(user.email)

    response = client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "5",
            "comment": "  Heavyweight and sharp.  ",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    review = db.session.scalar(select(ProductReview))
    assert review is not None
    assert review.rating == 5
    assert review.comment == "Heavyweight and sharp."
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.user_id == user.id
    assert review.product_id == _product_id(order)
    assert review.order_item_id == order.items[0].id
    html = _html(response)
    assert "Review published" in html
    assert "Heavyweight and sharp." in html
    assert "Verified buyer" in html


@pytest.mark.parametrize("rating", [1, 5])
def test_rating_boundaries_are_accepted(
    app: Flask,
    make_user,
    make_order,
    rating: int,
) -> None:
    user = make_user(email="boundary@example.com")
    order = _delivered_paid_order(user, make_order)

    review = _create_review(user, order, rating=rating)

    assert review.rating == rating


@pytest.mark.parametrize("rating", [0, 6, -1])
def test_rating_out_of_range_is_rejected(
    app: Flask,
    make_user,
    make_order,
    rating: int,
) -> None:
    user = make_user(email="range@example.com")
    order = _delivered_paid_order(user, make_order)

    with pytest.raises(ReviewValidationError):
        _create_review(user, order, rating=rating)

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


@pytest.mark.parametrize("rating", ["5", 4.5, Decimal("4"), True, False])
def test_non_integer_or_coerced_rating_is_rejected(
    app: Flask,
    make_user,
    make_order,
    rating: object,
) -> None:
    user = make_user(email="type@example.com")
    order = _delivered_paid_order(user, make_order)

    with pytest.raises(ReviewValidationError):
        create_product_review(
            user.id,
            _product_id(order),
            rating=rating,
            comment="Typed review.",
        )

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


@pytest.mark.parametrize("comment", ["", "   ", "\n\t"])
def test_empty_or_whitespace_comment_is_rejected(
    app: Flask,
    make_user,
    make_order,
    comment: str,
) -> None:
    user = make_user(email="empty@example.com")
    order = _delivered_paid_order(user, make_order)

    with pytest.raises(ReviewValidationError):
        _create_review(user, order, comment=comment)

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_comment_over_maximum_is_rejected(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="long@example.com")
    order = _delivered_paid_order(user, make_order)

    with pytest.raises(ReviewValidationError):
        _create_review(user, order, comment="a" * 2001)

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_comment_at_maximum_is_accepted(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="max@example.com")
    order = _delivered_paid_order(user, make_order)

    review = _create_review(user, order, comment="a" * 2000)

    assert len(review.comment) == 2000


def test_unicode_comment_is_preserved(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="unicode@example.com")
    order = _delivered_paid_order(user, make_order)

    review = _create_review(user, order, comment="Oversized — drop 014 🔥")

    assert review.comment == "Oversized — drop 014 🔥"


def test_duplicate_review_for_same_order_item_is_rejected(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="duplicate@example.com")
    order = _delivered_paid_order(user, make_order)
    _create_review(user, order)

    with pytest.raises(ReviewConflictError):
        _create_review(user, order)

    assert db.session.scalar(select(func.count(ProductReview.id))) == 1


def test_second_eligible_purchase_can_be_reviewed_separately(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="twice@example.com")
    first = _delivered_paid_order(user, make_order)
    second = _delivered_paid_order(user, make_order)

    first_review = _create_review(user, first, rating=5)
    second_review = _create_review(user, second, rating=3)

    assert first_review.order_item_id != second_review.order_item_id
    assert db.session.scalar(select(func.count(ProductReview.id))) == 2


def test_route_rejects_invalid_rating(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="route-rating@example.com")
    _delivered_paid_order(user, make_order)
    login(user.email)

    response = client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "0",
            "comment": "Out of range.",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(ProductReview.id))) == 0
    assert "between 1 and 5" in _html(response)


def test_route_rejects_non_numeric_rating(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="route-string@example.com")
    _delivered_paid_order(user, make_order)
    login(user.email)

    client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "five",
            "comment": "Not a number.",
        },
    )

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_route_rejects_overlong_comment(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="route-long@example.com")
    _delivered_paid_order(user, make_order)
    login(user.email)

    client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "4",
            "comment": "a" * 2001,
        },
    )

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_review_post_requires_csrf(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    user = make_user(email="csrf@example.com")
    _delivered_paid_order(user, make_order)
    login(user.email)

    response = client.post(
        "/products/void-tee/reviews",
        data={"rating": "5", "comment": "No token."},
    )

    assert response.status_code == 400
    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_anonymous_customer_cannot_submit_review(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    csrf_token,
) -> None:
    user = make_user(email="anonymous@example.com")
    order = _delivered_paid_order(user, make_order)

    response = client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/auth/login"),
            "rating": "5",
            "comment": "Anonymous.",
            "order_item_id": str(order.items[0].id),
        },
    )

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


def test_customer_cannot_review_another_users_order(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    owner = make_user(email="owner@example.com")
    other = make_user(email="other@example.com")
    order = _delivered_paid_order(owner, make_order)
    login(other.email)

    response = client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "5",
            "comment": "Not mine.",
            "order_item_id": str(order.items[0].id),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(ProductReview.id))) == 0
    assert "verified buyers only" in _html(response)


def test_forged_order_item_from_another_product_is_rejected(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="forger@example.com")
    _delivered_paid_order(user, make_order)
    hoodie_order = _delivered_paid_order(user, make_order, sku=HOODIE_SKU)
    login(user.email)

    response = client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "5",
            "comment": "Wrong product purchase.",
            "order_item_id": str(hoodie_order.items[0].id),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert db.session.scalar(select(func.count(ProductReview.id))) == 0
    assert "not eligible for this product" in _html(response)


def test_non_numeric_order_item_id_is_rejected(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="bad-item@example.com")
    _delivered_paid_order(user, make_order)
    login(user.email)

    client.post(
        "/products/void-tee/reviews",
        data={
            "csrf_token": csrf_token("/product/void-tee"),
            "rating": "5",
            "comment": "Bad reference.",
            "order_item_id": "abc",
        },
    )

    assert db.session.scalar(select(func.count(ProductReview.id))) == 0


@pytest.mark.parametrize(
    ("status", "payment_status", "eligible"),
    [
        ("pending", "unpaid", False),
        ("processing", "paid", False),
        ("shipped", "paid", False),
        ("delivered", "unpaid", False),
        ("delivered", "refunded", False),
        ("cancelled", "unpaid", False),
        ("delivered", "paid", True),
    ],
)
def test_eligibility_requires_delivered_and_paid(
    app: Flask,
    make_user,
    make_order,
    status: str,
    payment_status: str,
    eligible: bool,
) -> None:
    user = make_user(email="eligibility@example.com")
    order = make_order(user, status=status, payment_status=payment_status)

    result = get_review_eligibility(user.id, _product_id(order))

    assert result.eligible is eligible
    if eligible:
        assert result.order_item_id == order.items[0].id
        assert result.order_number == order.order_number
    else:
        assert "Reviews" in result.message or "verified" in result.message


def test_customer_without_purchase_is_not_eligible(
    app: Flask,
    make_user,
    seeded_catalog,
) -> None:
    user = make_user(email="nopurchase@example.com")
    product = db.session.scalar(select(Product).where(Product.slug == "void-tee"))
    assert product is not None

    result = get_review_eligibility(user.id, product.id)

    assert result.eligible is False
    assert "verified buyers only" in result.message


def test_eligibility_reports_already_reviewed_purchase(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="already@example.com")
    order = _delivered_paid_order(user, make_order)
    _create_review(user, order)

    result = get_review_eligibility(user.id, _product_id(order))

    assert result.eligible is False
    assert "already reviewed" in result.message


def test_owner_can_edit_rating_and_comment(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="editor@example.com")
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order, rating=3, comment="Initial verdict.")
    login(user.email)

    response = client.post(
        f"/reviews/{review.id}/edit",
        data={
            "csrf_token": csrf_token(f"/reviews/{review.id}/edit"),
            "rating": "5",
            "comment": "  Revised verdict.  ",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.refresh(review)
    assert review.rating == 5
    assert review.comment == "Revised verdict."
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert "Review updated" in _html(response)


def test_another_customer_cannot_edit_review(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    owner = make_user(email="review-owner@example.com")
    other = make_user(email="review-other@example.com")
    order = _delivered_paid_order(owner, make_order)
    review = _create_review(owner, order, rating=4, comment="Owner only.")
    login(other.email)

    get_response = client.get(f"/reviews/{review.id}/edit")
    post_response = client.post(
        f"/reviews/{review.id}/edit",
        data={
            "csrf_token": csrf_token("/auth/account"),
            "rating": "1",
            "comment": "Hijacked.",
        },
    )

    assert get_response.status_code == 404
    assert post_response.status_code == 404
    db.session.refresh(review)
    assert review.rating == 4
    assert review.comment == "Owner only."


def test_edit_cannot_change_relationships_author_or_status(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="immutable@example.com")
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order, rating=4, comment="Original.")
    original_product_id = review.product_id
    original_order_item_id = review.order_item_id
    original_user_id = review.user_id
    login(user.email)

    client.post(
        f"/reviews/{review.id}/edit",
        data={
            "csrf_token": csrf_token(f"/reviews/{review.id}/edit"),
            "rating": "5",
            "comment": "Updated comment.",
            "product_id": "999",
            "order_item_id": "999",
            "user_id": "999",
            "status": "hidden",
        },
    )

    db.session.refresh(review)
    assert review.product_id == original_product_id
    assert review.order_item_id == original_order_item_id
    assert review.user_id == original_user_id
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.comment == "Updated comment."


def test_hidden_review_stays_hidden_after_edit(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    user = make_user(email="hidden-editor@example.com")
    admin = make_user(email="hidden-admin@example.com", role=ROLE_ADMIN)
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order, rating=5, comment="Hidden soon.")
    result = set_review_visibility(
        review.id,
        admin.id,
        REVIEW_STATUS_HIDDEN,
        reason="Needs review.",
    )
    moderated_at = result.review.moderated_at
    login(user.email)

    client.post(
        f"/reviews/{review.id}/edit",
        data={
            "csrf_token": csrf_token(f"/reviews/{review.id}/edit"),
            "rating": "4",
            "comment": "Edited while hidden.",
            "status": "published",
        },
    )

    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_HIDDEN
    assert review.moderated_by_user_id == admin.id
    assert review.moderated_at == moderated_at
    assert review.moderation_reason == "Needs review."
    assert get_review_summary(review.product_id).total == 0


def test_anonymous_customer_cannot_edit_review(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    user = make_user(email="anon-editor@example.com")
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order)

    response = client.get(f"/reviews/{review.id}/edit")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_product_page_shows_average_count_and_distribution(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    first = make_user(email="five@example.com", full_name="Five Star")
    second = make_user(email="three@example.com", full_name="Three Star")
    first_order = _delivered_paid_order(first, make_order)
    second_order = _delivered_paid_order(second, make_order)
    _create_review(first, first_order, rating=5, comment="Five.")
    _create_review(second, second_order, rating=3, comment="Three.")

    summary = get_review_summary(_product_id(first_order))
    assert summary.average == 4.0
    assert summary.total == 2
    assert summary.distribution[5] == 1
    assert summary.distribution[3] == 1
    assert summary.distribution[1] == 0

    html = _html(client.get("/product/void-tee"))
    assert "4.0" in html
    assert "2 published reviews" in html
    assert "Five." in html
    assert "Three." in html
    assert "Verified buyer" in html


def test_hidden_review_is_excluded_from_public_page_and_summary(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    author = make_user(email="hidden-author@example.com", full_name="Hidden Author")
    admin = make_user(email="moderator@example.com", role=ROLE_ADMIN)
    order = _delivered_paid_order(author, make_order)
    review = _create_review(author, order, rating=1, comment="Will be hidden.")
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Abusive.")

    summary = get_review_summary(review.product_id)
    html = _html(client.get("/product/void-tee"))

    assert summary.total == 0
    assert summary.average == 0.0
    assert "Will be hidden." not in html
    assert "No published reviews" in html


def test_zero_review_product_renders_empty_state(
    client: FlaskClient,
    seeded_catalog,
) -> None:
    response = client.get("/product/void-tee")

    assert response.status_code == 200
    html = _html(response)
    assert "No published reviews" in html
    assert "Be the first to" in html
    assert "0.0" not in html


def test_product_page_paginates_published_reviews(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    for index in range(6):
        user = make_user(email=f"pager{index}@example.com", full_name=f"Pager {index}")
        order = _delivered_paid_order(user, make_order)
        _create_review(user, order, rating=5, comment=f"Paged comment {index}.")

    first_page = _html(client.get("/product/void-tee"))
    second_page = _html(client.get("/product/void-tee?page=2"))

    assert first_page.count('class="review-card"') == 5
    assert second_page.count('class="review-card"') == 1
    assert 'aria-label="Review pagination"' in first_page
    assert "Paged comment" in first_page
    assert "Paged comment" in second_page


def test_reviewer_email_is_never_exposed_publicly(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    user = make_user(email="private@example.com", full_name="Private Buyer")
    order = _delivered_paid_order(user, make_order)
    _create_review(user, order, comment="Public comment.")

    html = _html(client.get("/product/void-tee"))

    assert "Private Buyer" in html
    assert "private@example.com" not in html


def test_review_comment_is_html_escaped(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    user = make_user(email="xss@example.com")
    order = _delivered_paid_order(user, make_order)
    payload = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'
    _create_review(user, order, comment=payload)

    html = _html(client.get("/product/void-tee"))

    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html


def test_customer_review_history_includes_hidden_reviews(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    owner = make_user(email="history@example.com", full_name="History Owner")
    other = make_user(email="history-other@example.com", full_name="History Other")
    admin = make_user(email="history-admin@example.com", role=ROLE_ADMIN)
    owner_order = _delivered_paid_order(owner, make_order)
    other_order = _delivered_paid_order(other, make_order)
    review = _create_review(owner, owner_order, comment="Owner history entry.")
    _create_review(other, other_order, comment="Other history entry.")
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Check.")
    login(owner.email)

    html = _html(client.get("/account/reviews"))

    assert "Owner history entry." in html
    assert "Other history entry." not in html
    assert "Hidden" in html
    assert f"/reviews/{review.id}/edit" in html


def test_customer_history_paginates_own_reviews(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    user = make_user(email="history-pager@example.com")
    for index in range(11):
        order = _delivered_paid_order(user, make_order)
        _create_review(user, order, comment=f"History comment {index}.")
    login(user.email)

    first = get_user_reviews(user.id, page=1, per_page=10)
    second = get_user_reviews(user.id, page=2, per_page=10)

    assert first.total == 11
    assert len(first.items) == 10
    assert len(second.items) == 1
    html = _html(client.get("/account/reviews?page=2"))
    assert "History comment" in html


def test_unique_order_item_constraint_is_enforced(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="unique@example.com")
    order = _delivered_paid_order(user, make_order)
    _create_review(user, order)

    duplicate = ProductReview(
        product_id=_product_id(order),
        user_id=user.id,
        order_item_id=order.items[0].id,
        rating=4,
        comment="Duplicate row.",
    )
    db.session.add(duplicate)

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()

    assert db.session.scalar(select(func.count(ProductReview.id))) == 1


def test_rating_check_constraint_is_enforced(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="db-rating@example.com")
    order = _delivered_paid_order(user, make_order)

    db.session.add(
        ProductReview(
            product_id=_product_id(order),
            user_id=user.id,
            order_item_id=order.items[0].id,
            rating=0,
            comment="Invalid rating.",
        )
    )

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_comment_check_constraint_is_enforced(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="db-comment@example.com")
    order = _delivered_paid_order(user, make_order)

    db.session.add(
        ProductReview(
            product_id=_product_id(order),
            user_id=user.id,
            order_item_id=order.items[0].id,
            rating=5,
            comment="",
        )
    )

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_hidden_review_requires_a_moderation_reason_at_database_level(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="db-hidden@example.com")
    order = _delivered_paid_order(user, make_order)

    db.session.add(
        ProductReview(
            product_id=_product_id(order),
            user_id=user.id,
            order_item_id=order.items[0].id,
            rating=5,
            comment="Hidden without reason.",
            status=REVIEW_STATUS_HIDDEN,
            moderation_reason=None,
        )
    )

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_invalid_order_item_foreign_key_is_rejected(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="db-fk@example.com")
    order = _delivered_paid_order(user, make_order)

    db.session.add(
        ProductReview(
            product_id=_product_id(order),
            user_id=user.id,
            order_item_id=999_999,
            rating=5,
            comment="Missing order line.",
        )
    )

    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_deactivating_product_preserves_reviews_and_order_history(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    user = make_user(email="deactivate@example.com")
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order, comment="Preserved review.")
    product = db.session.get(Product, review.product_id)
    assert product is not None
    product.is_active = False
    db.session.commit()
    login(user.email)

    assert db.session.get(ProductReview, review.id) is not None
    assert db.session.scalar(select(func.count(OrderItem.id))) >= 1
    assert client.get("/product/void-tee").status_code == 404
    history = client.get(f"/orders/{order.order_number}")
    assert history.status_code == 200
    assert "Void Tee" in _html(history)


def test_concurrent_duplicate_insert_creates_at_most_one_review(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="race@example.com")
    order = _delivered_paid_order(user, make_order)
    product_id = _product_id(order)
    user_id = user.id
    order_item_id = order.items[0].id

    barrier = Barrier(2)
    outcomes: list[str] = []

    def worker() -> None:
        with app.app_context():
            barrier.wait(timeout=10)
            db.session.add(
                ProductReview(
                    product_id=product_id,
                    user_id=user_id,
                    order_item_id=order_item_id,
                    rating=5,
                    comment="Concurrent insert.",
                )
            )
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                outcomes.append("conflict")
            else:
                outcomes.append("created")
            finally:
                db.session.remove()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _index: worker(), range(2)))

    assert sorted(outcomes) == ["conflict", "created"]
    assert db.session.scalar(select(func.count(ProductReview.id))) == 1


def test_service_update_preserves_relationships(
    app: Flask,
    make_user,
    make_order,
) -> None:
    user = make_user(email="service-edit@example.com")
    order = _delivered_paid_order(user, make_order)
    review = _create_review(user, order, rating=2, comment="Before.")

    updated = update_product_review(
        user.id,
        review.id,
        rating=4,
        comment="After.",
    )

    assert updated.rating == 4
    assert updated.comment == "After."
    assert updated.product_id == review.product_id
    assert updated.order_item_id == review.order_item_id
    assert updated.user_id == user.id


def test_service_update_rejects_other_owner(
    app: Flask,
    make_user,
    make_order,
) -> None:
    owner = make_user(email="service-owner@example.com")
    other = make_user(email="service-other@example.com")
    order = _delivered_paid_order(owner, make_order)
    review = _create_review(owner, order, rating=5, comment="Mine.")

    with pytest.raises(ReviewNotFound):
        update_product_review(other.id, review.id, rating=1, comment="Not mine.")


def test_eligibility_error_when_service_called_without_purchase(
    app: Flask,
    make_user,
    seeded_catalog,
) -> None:
    user = make_user(email="service-nopurchase@example.com")
    product = db.session.scalar(select(Product).where(Product.slug == "void-tee"))
    assert product is not None

    with pytest.raises(ReviewEligibilityError):
        create_product_review(
            user.id,
            product.id,
            rating=5,
            comment="No purchase.",
        )
