"""Authentication forms and input normalization."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

from app.models.user import normalize_email


def _strip(value: str | None) -> str | None:
    return value.strip() if isinstance(value, str) else value


def _normalize_email(value: str | None) -> str | None:
    return normalize_email(value) if isinstance(value, str) else value


class RegistrationForm(FlaskForm):
    """Create a customer account; role is never accepted from the client."""

    full_name = StringField(
        "Full name",
        filters=[_strip],
        validators=[DataRequired(), Length(max=120)],
    )
    email = StringField(
        "Email",
        filters=[_strip, _normalize_email],
        validators=[DataRequired(), Email(), Length(max=255)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    """Authenticate an existing account."""

    email = StringField(
        "Email",
        filters=[_strip, _normalize_email],
        validators=[DataRequired(), Email(), Length(max=255)],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(max=128)],
    )
    remember = BooleanField("Keep me signed in")
    next = HiddenField()
    submit = SubmitField("Sign in")
