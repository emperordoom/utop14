"""Payment initiation and simulation forms."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import HiddenField, RadioField, SubmitField
from wtforms.fields.choices import SelectChoice
from wtforms.validators import DataRequired, Length

from app.payments.providers.simulated import (
    SIMULATED_OUTCOME_FAILURE,
    SIMULATED_OUTCOME_SUCCESS,
)


class PaymentInitiationForm(FlaskForm):
    """Start a new server-priced payment attempt."""

    idempotency_key = HiddenField(
        validators=[DataRequired(), Length(min=8, max=64)],
    )
    submit = SubmitField("Start payment")


class SimulationForm(FlaskForm):
    """Choose a deterministic simulated payment outcome."""

    outcome = RadioField(
        "Simulated outcome",
        choices=[
            SelectChoice(SIMULATED_OUTCOME_SUCCESS, "Simulate successful payment"),
            SelectChoice(SIMULATED_OUTCOME_FAILURE, "Simulate failed payment"),
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Run simulation")
