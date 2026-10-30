"""Staff order-management forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional


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
