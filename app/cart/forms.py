"""Cart forms and server-side quantity validation."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import InputRequired, NumberRange

from app.services.cart import MAX_CART_QUANTITY


class AddToCartForm(FlaskForm):
    """Add one variant to the signed-in user's cart."""

    variant_id = IntegerField(
        "Variant",
        validators=[InputRequired(), NumberRange(min=1)],
    )
    quantity = IntegerField(
        "Quantity",
        default=1,
        validators=[InputRequired(), NumberRange(min=1, max=MAX_CART_QUANTITY)],
    )
    submit = SubmitField("Add to cart")


class UpdateCartForm(FlaskForm):
    """Update one cart line quantity."""

    quantity = IntegerField(
        "Quantity",
        validators=[InputRequired(), NumberRange(min=1, max=MAX_CART_QUANTITY)],
    )
    submit = SubmitField("Update")
