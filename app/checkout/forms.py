"""Checkout address and recipient form."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class CheckoutForm(FlaskForm):
    """Collect a validated shipping destination for an order."""

    recipient_name = StringField(
        "Recipient name",
        filters=[_strip],
        validators=[DataRequired(), Length(max=120)],
    )
    recipient_phone = StringField(
        "Phone",
        filters=[_strip],
        validators=[
            DataRequired(),
            Length(max=32),
            Regexp(
                r"^[0-9+()\-.\s]{6,32}$",
                message="Enter a valid phone number.",
            ),
        ],
    )
    shipping_address = StringField(
        "Address",
        filters=[_strip],
        validators=[DataRequired(), Length(max=255)],
    )
    shipping_city = StringField(
        "City",
        filters=[_strip],
        validators=[DataRequired(), Length(max=120)],
    )
    shipping_postal_code = StringField(
        "Postal code",
        filters=[_strip],
        validators=[
            DataRequired(),
            Length(max=20),
            Regexp(
                r"^[A-Za-z0-9][A-Za-z0-9\s-]{1,19}$",
                message="Enter a valid postal code.",
            ),
        ],
    )
    submit = SubmitField("Place order")
