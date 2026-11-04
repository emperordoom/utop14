"""Customer product-review forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, IntegerField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, InputRequired, Length, NumberRange, Optional

from app.models.product_review import REVIEW_MAX_COMMENT_LENGTH


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class ReviewForm(FlaskForm):
    """Submit one verified-purchase review."""

    rating = IntegerField(
        "Rating",
        validators=[InputRequired(), NumberRange(min=1, max=5)],
    )
    comment = TextAreaField(
        "Review",
        filters=[_strip],
        validators=[
            DataRequired(),
            Length(min=1, max=REVIEW_MAX_COMMENT_LENGTH),
        ],
    )
    order_item_id = HiddenField(validators=[Optional()])
    submit = SubmitField("Publish review")


class ReviewEditForm(FlaskForm):
    """Edit the owner's rating and comment only."""

    rating = IntegerField(
        "Rating",
        validators=[InputRequired(), NumberRange(min=1, max=5)],
    )
    comment = TextAreaField(
        "Review",
        filters=[_strip],
        validators=[
            DataRequired(),
            Length(min=1, max=REVIEW_MAX_COMMENT_LENGTH),
        ],
    )
    submit = SubmitField("Save review")
