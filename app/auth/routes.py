"""Authentication routes for registration, login, logout and account."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from flask import flash, g, redirect, render_template, request, session, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth import auth_bp
from app.auth.forms import LoginForm, RegistrationForm
from app.extensions import db
from app.models.user import ROLE_CUSTOMER, User

_SAFE_NEXT_MAX_LENGTH = 2048


def _safe_next_url(target: str | None) -> str | None:
    """Return a local redirect target, or ``None`` for unsafe input."""
    if target is None:
        return None

    candidate = target.strip()
    if not candidate or len(candidate) > _SAFE_NEXT_MAX_LENGTH:
        return None
    if not candidate.startswith("/") or candidate.startswith("//"):
        return None
    if "\\" in candidate or "\r" in candidate or "\n" in candidate:
        return None
    if candidate.lower().startswith(("/%2f", "/%5c")):
        return None

    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return None
    return candidate


def _clear_session() -> None:
    """Clear the session and any CSRF token cached on the app context."""
    session.clear()
    g.pop("csrf_token", None)


@auth_bp.route("/register", methods=["GET", "POST"])
def register() -> ResponseReturnValue:
    """Register a customer account with a server-assigned role."""
    if current_user.is_authenticated:
        return redirect(url_for("auth.account"))

    form = RegistrationForm()
    if form.validate_on_submit():
        existing = db.session.scalar(select(User).where(User.email == form.email.data))
        if existing is not None:
            form.email.errors.append("An account with that email already exists.")
        else:
            user = User(
                email=form.email.data,
                full_name=form.full_name.data,
                role=ROLE_CUSTOMER,
            )
            user.set_password(form.password.data)
            user.last_login_at = datetime.now(UTC)
            db.session.add(user)

            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                form.email.errors.append("An account with that email already exists.")
            else:
                _clear_session()
                login_user(user)
                flash("Account created. Welcome to UTOP14.", "success")
                return redirect(url_for("auth.account"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login() -> ResponseReturnValue:
    """Authenticate an active account and update its last login time."""
    if current_user.is_authenticated:
        return redirect(_safe_next_url(request.args.get("next")) or url_for("storefront.home"))

    form = LoginForm()
    if not form.next.data:
        form.next.data = request.args.get("next", "")

    if form.validate_on_submit():
        user = db.session.scalar(select(User).where(User.email == form.email.data))
        if user is None or not user.is_active or not user.verify_password(form.password.data):
            flash("Invalid email or password.", "error")
        else:
            user.last_login_at = datetime.now(UTC)
            db.session.commit()

            _clear_session()
            login_user(user, remember=form.remember.data)
            flash("Signed in. Welcome back.", "success")
            destination = _safe_next_url(form.next.data) or url_for("storefront.home")
            return redirect(destination)

    return render_template("auth/login.html", form=form)


@auth_bp.post("/logout")
@login_required
def logout() -> ResponseReturnValue:
    """End the current session.  Logout is POST-only and CSRF protected."""
    logout_user()
    _clear_session()
    flash("Signed out.", "info")
    return redirect(url_for("storefront.home"))


@auth_bp.get("/account")
@login_required
def account() -> ResponseReturnValue:
    """Show the signed-in user's own account details."""
    return render_template("auth/account.html")
