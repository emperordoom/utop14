"""Staff order-management and catalog-administration forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    IntegerField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, InputRequired, Length, NumberRange, Optional


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class OrderStatusForm(FlaskForm):
    """Choose one permitted order lifecycle transition."""

    status = SelectField("New status", choices=[], validators=[DataRequired()])
    reason = TextAreaField(
        "Cancellation reason (optional)",
        filters=[_strip],
        validators=[Optional(), Length(max=500)],
    )
    submit = SubmitField("Update status")


class CategoryForm(FlaskForm):
    """Create or edit a catalog category."""

    name = StringField(
        "Name",
        filters=[_strip],
        validators=[DataRequired(), Length(max=80)],
    )
    slug = StringField(
        "Slug",
        filters=[_strip],
        validators=[DataRequired(), Length(max=80)],
    )
    description = TextAreaField(
        "Description",
        filters=[_strip],
        validators=[Optional(), Length(max=1000)],
    )
    icon = StringField(
        "Icon path",
        filters=[_strip],
        validators=[DataRequired(), Length(max=255)],
    )
    position = IntegerField(
        "Position",
        default=0,
        validators=[InputRequired(), NumberRange(min=0, max=9999)],
    )
    submit = SubmitField("Save category")


class ProductForm(FlaskForm):
    """Create or edit a catalog product."""

    category_id = SelectField(
        "Category",
        coerce=int,
        choices=[],
        validators=[DataRequired()],
    )
    name = StringField(
        "Name",
        filters=[_strip],
        validators=[DataRequired(), Length(max=120)],
    )
    slug = StringField(
        "Slug",
        filters=[_strip],
        validators=[DataRequired(), Length(max=120)],
    )
    description = TextAreaField(
        "Description",
        filters=[_strip],
        validators=[Optional(), Length(max=5000)],
    )
    price = StringField(
        "Price",
        filters=[_strip],
        validators=[DataRequired(), Length(max=15)],
    )
    image_path = StringField(
        "Card image path",
        filters=[_strip],
        validators=[DataRequired(), Length(max=255)],
    )
    image_alt = StringField(
        "Card image alt text",
        filters=[_strip],
        validators=[Optional(), Length(max=255)],
    )
    badge = StringField(
        "Badge",
        filters=[_strip],
        validators=[Optional(), Length(max=40)],
    )
    submit = SubmitField("Save product")


class VariantForm(FlaskForm):
    """Create or edit a size/colour inventory variant."""

    size = StringField(
        "Size",
        filters=[_strip],
        validators=[DataRequired(), Length(max=20)],
    )
    color = StringField(
        "Colour",
        filters=[_strip],
        validators=[DataRequired(), Length(max=40)],
    )
    sku = StringField(
        "SKU",
        filters=[_strip],
        validators=[DataRequired(), Length(max=64)],
    )
    stock = IntegerField(
        "Stock",
        validators=[InputRequired(), NumberRange(min=0, max=1_000_000)],
    )
    submit = SubmitField("Save variant")


class ImageForm(FlaskForm):
    """Create or edit a product gallery image path."""

    image_path = StringField(
        "Image path",
        filters=[_strip],
        validators=[DataRequired(), Length(max=255)],
    )
    alt_text = StringField(
        "Alt text",
        filters=[_strip],
        validators=[Optional(), Length(max=255)],
    )
    position = IntegerField(
        "Position",
        default=0,
        validators=[InputRequired(), NumberRange(min=0, max=9999)],
    )
    submit = SubmitField("Save image")


class StockForm(FlaskForm):
    """Set an absolute stock value for one variant."""

    stock = IntegerField(
        "Stock",
        validators=[InputRequired(), NumberRange(min=0, max=1_000_000)],
    )
    submit = SubmitField("Update stock")


class ActionForm(FlaskForm):
    """CSRF-only form for activation, deactivation and delete actions."""

    submit = SubmitField("Confirm")


class PaymentProofRejectForm(FlaskForm):
    """Reject one payment proof with a mandatory reason."""

    reason = TextAreaField(
        "Rejection reason",
        filters=[_strip],
        validators=[DataRequired(), Length(max=500)],
    )
    submit = SubmitField("Reject proof")
