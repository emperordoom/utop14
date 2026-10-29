"""Customer order cancellation form."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField
from wtforms.validators import Length, Optional


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


class CancelOrderForm(FlaskForm):
    """Optional cancellation reason with a bounded length."""

    reason = TextAreaField(
        "Reason (optional)",
        filters=[_strip],
        validators=[Optional(), Length(max=500)],
    )
    submit = SubmitField("Confirm cancellation")
