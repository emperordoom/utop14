"""Integration tests for admin product-review moderation."""

from __future__ import annotations

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import func, select

from app.extensions import db
from app.models import Order, ProductReview, ProductVariant
from app.models.product_review import REVIEW_STATUS_HIDDEN, REVIEW_STATUS_PUBLISHED
from app.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_OPERATOR
from app.services.reviews import (
    create_product_review,
    get_review_summary,
    set_review_visibility,
)

VOID_TEE_SKU = "UT014-VT-WBK-M"
HOODIE_SKU = "UT014-SH-FCH-M"


def _delivered_paid_order(user, make_order, *, sku: str = VOID_TEE_SKU) -> Order:
    return make_order(user, sku=sku, status="delivered", payment_status="paid")


def _create_review(user, order: Order, *, rating: int = 5, comment: str = "Solid."):
    product_id = order.items[0].product_id
    assert product_id is not None
    return create_product_review(
        user.id,
        product_id,
        rating=rating,
        comment=comment,
    )


def _html(response) -> str:
    return response.get_data(as_text=True)


def _admin_review(
    make_user,
    make_order,
    *,
    email: str = "reviewer@example.com",
    name: str = "Reviewer One",
    sku: str = VOID_TEE_SKU,
    rating: int = 5,
    comment: str = "A review body.",
) -> tuple[ProductReview, object]:
    user = make_user(email=email, full_name=name)
    order = _delivered_paid_order(user, make_order, sku=sku)
    return _create_review(user, order, rating=rating, comment=comment), user


def test_admin_can_list_reviews(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="list-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    response = client.get("/admin/reviews")

    assert response.status_code == 200
    html = _html(response)
    assert "Void Tee" in html
    assert "Reviewer One" in html
    assert "Published" in html
    assert f"/admin/reviews/{review.id}" in html


def test_admin_can_open_review_detail(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="detail-admin@example.com", role=ROLE_ADMIN)
    review, user = _admin_review(make_user, make_order)
    login(admin.email)

    response = client.get(f"/admin/reviews/{review.id}")

    assert response.status_code == 200
    html = _html(response)
    assert review.comment in html
    assert user.email in html
    assert "Verified buyer" in html
    assert "Hide review" in html


def test_admin_can_hide_review_with_reason(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="hide-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    response = client.post(
        f"/admin/reviews/{review.id}/hide",
        data={
            "csrf_token": csrf_token(f"/admin/reviews/{review.id}"),
            "reason": "  Abusive language.  ",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_HIDDEN
    assert review.moderated_by_user_id == admin.id
    assert review.moderated_at is not None
    assert review.moderation_reason == "Abusive language."
    assert review.rating == 5
    assert review.comment == "A review body."
    assert get_review_summary(review.product_id).total == 0
    assert "Review hidden" in _html(response)


def test_admin_can_publish_hidden_review(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="publish-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Temporary.")
    login(admin.email)

    response = client.post(
        f"/admin/reviews/{review.id}/publish",
        data={"csrf_token": csrf_token(f"/admin/reviews/{review.id}")},
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.moderated_by_user_id == admin.id
    assert review.moderated_at is not None
    assert review.moderation_reason == "Temporary."
    assert get_review_summary(review.product_id).total == 1
    assert "Review published" in _html(response)


def test_hiding_without_reason_is_rejected(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="noreason-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    response = client.post(
        f"/admin/reviews/{review.id}/hide",
        data={
            "csrf_token": csrf_token(f"/admin/reviews/{review.id}"),
            "reason": "   ",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.moderated_at is None
    assert "moderation reason is required" in _html(response)


def test_hiding_with_overlong_reason_is_rejected(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="longreason-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    client.post(
        f"/admin/reviews/{review.id}/hide",
        data={
            "csrf_token": csrf_token(f"/admin/reviews/{review.id}"),
            "reason": "a" * 501,
        },
    )

    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.moderated_at is None


def test_operator_cannot_access_review_moderation(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    operator = make_user(email="operator@example.com", role=ROLE_OPERATOR)
    review, _user = _admin_review(make_user, make_order)
    login(operator.email)
    token = csrf_token("/auth/account")

    assert client.get("/admin/reviews").status_code == 403
    assert client.get(f"/admin/reviews/{review.id}").status_code == 403
    hide_response = client.post(
        f"/admin/reviews/{review.id}/hide",
        data={"csrf_token": token, "reason": "No."},
    )
    assert hide_response.status_code == 403
    publish_response = client.post(
        f"/admin/reviews/{review.id}/publish",
        data={"csrf_token": token},
    )
    assert publish_response.status_code == 403


def test_customer_cannot_access_review_moderation(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    customer = make_user(email="customer-role@example.com", role=ROLE_CUSTOMER)
    review, _user = _admin_review(make_user, make_order)
    login(customer.email)
    token = csrf_token("/auth/account")

    assert client.get("/admin/reviews").status_code == 403
    assert client.get(f"/admin/reviews/{review.id}").status_code == 403
    hide_response = client.post(
        f"/admin/reviews/{review.id}/hide",
        data={"csrf_token": token, "reason": "No."},
    )
    assert hide_response.status_code == 403
    publish_response = client.post(
        f"/admin/reviews/{review.id}/publish",
        data={"csrf_token": token},
    )
    assert publish_response.status_code == 403


def test_anonymous_user_is_redirected_to_login(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
) -> None:
    review, _user = _admin_review(make_user, make_order)

    response = client.get("/admin/reviews")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
    assert client.get(f"/admin/reviews/{review.id}").status_code == 302


def test_get_detail_never_changes_moderation_status(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="get-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Hidden.")
    login(admin.email)

    for _index in range(3):
        assert client.get(f"/admin/reviews/{review.id}").status_code == 200

    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_HIDDEN
    assert client.get(f"/admin/reviews/{review.id}/hide").status_code == 405
    assert client.get(f"/admin/reviews/{review.id}/publish").status_code == 405


def test_hide_and_publish_require_csrf(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="csrf-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    hide_response = client.post(
        f"/admin/reviews/{review.id}/hide",
        data={"reason": "No token."},
    )
    publish_response = client.post(f"/admin/reviews/{review.id}/publish", data={})

    assert hide_response.status_code == 400
    assert publish_response.status_code == 400

    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_PUBLISHED


def test_admin_review_filters(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="filter-admin@example.com", role=ROLE_ADMIN)
    published, _first = _admin_review(
        make_user,
        make_order,
        email="ada@example.com",
        name="Ada Published",
        rating=5,
        comment="Published tee review.",
    )
    hidden, _second = _admin_review(
        make_user,
        make_order,
        email="bob@example.com",
        name="Bob Hidden",
        sku=HOODIE_SKU,
        rating=2,
        comment="Hidden hoodie review.",
    )
    set_review_visibility(hidden.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Check.")
    login(admin.email)

    hidden_html = _html(client.get("/admin/reviews?status=hidden"))
    assert "Bob Hidden" in hidden_html
    assert "Ada Published" not in hidden_html

    rating_html = _html(client.get("/admin/reviews?rating=5"))
    assert "Ada Published" in rating_html
    assert "Bob Hidden" not in rating_html

    product_html = _html(client.get("/admin/reviews?product=hoodie"))
    assert "Bob Hidden" in product_html
    assert "Ada Published" not in product_html

    reviewer_html = _html(client.get("/admin/reviews?q=bob@example.com"))
    assert "Bob Hidden" in reviewer_html
    assert "Ada Published" not in reviewer_html

    published_html = _html(client.get("/admin/reviews?status=published"))
    assert "Ada Published" in published_html
    assert "Bob Hidden" not in published_html


def test_admin_detail_shows_moderation_record(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="record-admin@example.com", full_name="Mod Admin", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Policy breach.")
    login(admin.email)

    html = _html(client.get(f"/admin/reviews/{review.id}"))

    assert "Policy breach." in html
    assert "Mod Admin" in html
    assert "Hidden" in html
    assert "Publish review" in html


def test_hide_unknown_review_returns_404(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="missing-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order)
    login(admin.email)

    response = client.post(
        "/admin/reviews/999999/hide",
        data={
            "csrf_token": csrf_token(f"/admin/reviews/{review.id}"),
            "reason": "Missing.",
        },
    )

    assert response.status_code == 404


def test_admin_list_paginates(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
) -> None:
    admin = make_user(email="pager-admin@example.com", role=ROLE_ADMIN)
    variant = db.session.scalar(select(ProductVariant).where(ProductVariant.sku == VOID_TEE_SKU))
    assert variant is not None
    variant.stock = 100
    db.session.commit()
    for index in range(21):
        reviewer = make_user(email=f"bulk{index}@example.com", full_name=f"Bulk {index}")
        order = _delivered_paid_order(reviewer, make_order)
        _create_review(reviewer, order, comment=f"Bulk review {index}.")
    login(admin.email)

    first = _html(client.get("/admin/reviews"))
    second = _html(client.get("/admin/reviews?page=2"))

    assert first.count("<tr>") >= 21
    assert "Bulk " in first
    assert "Bulk " in second
    assert db.session.scalar(select(func.count(ProductReview.id))) == 21


def test_publish_route_keeps_original_rating_and_comment(
    app: Flask,
    client: FlaskClient,
    make_user,
    make_order,
    login,
    csrf_token,
) -> None:
    admin = make_user(email="preserve-admin@example.com", role=ROLE_ADMIN)
    review, _user = _admin_review(make_user, make_order, rating=4, comment="Preserve me.")
    original_rating = review.rating
    original_comment = review.comment
    set_review_visibility(review.id, admin.id, REVIEW_STATUS_HIDDEN, reason="Hold.")
    login(admin.email)

    client.post(
        f"/admin/reviews/{review.id}/publish",
        data={"csrf_token": csrf_token(f"/admin/reviews/{review.id}")},
    )

    db.session.refresh(review)
    assert review.status == REVIEW_STATUS_PUBLISHED
    assert review.rating == original_rating
    assert review.comment == original_comment
