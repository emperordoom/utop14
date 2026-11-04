"""Authentication routes for registration, login, logout and account."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from flask import abort, flash, g, redirect, render_template, request, send_file, session, url_for
from flask.typing import ResponseReturnValue
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.auth import auth_bp
from app.auth.forms import (
    AvatarUploadForm,
    LoginForm,
    ProfileForm,
    RegistrationForm,
    RemoveAvatarForm,
)
from app.auth.passwords import verify_dummy_password
from app.extensions import db
from app.models.security_event import (
    SECURITY_REASON_INACTIVE_ACCOUNT,
    SECURITY_REASON_INVALID_PASSWORD,
    SECURITY_REASON_UNKNOWN_ACCOUNT,
)
from app.models.user import ROLE_CUSTOMER, User
from app.services.avatars import (
    AvatarError,
    AvatarValidationError,
    avatar_file_exists,
    avatar_file_path,
    remove_avatar,
    save_avatar,
)
from app.services.profiles import (
    ProfileConflictError,
    ProfileError,
    ProfileValidationError,
    update_profile,
)
from app.services.security_events import (
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_REGISTRATION,
    record_login_failed,
    record_login_succeeded,
    record_logout,
)

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


def _render_account(
    *,
    profile_form: ProfileForm | None = None,
    avatar_form: AvatarUploadForm | None = None,
) -> str:
    """Render the account page with both profile and avatar forms."""
    return render_template(
        "auth/account.html",
        profile_form=profile_form or ProfileForm(obj=current_user),
        avatar_form=avatar_form or AvatarUploadForm(),
        remove_avatar_form=RemoveAvatarForm(),
        has_avatar_file=avatar_file_exists(current_user.avatar_filename),
    )


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
                # Flush so the generated ID is available before commit; every
                # field needed by the security event is captured while loaded.
                db.session.flush()
                user_id = user.id
                user_email = user.email
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                form.email.errors.append("An account with that email already exists.")
            else:
                # Reload the committed user, then release the request session's
                # connection before independent event storage.  No business
                # changes are pending after the commit.
                db.session.refresh(user)
                _clear_session()
                login_user(user)
                # Rollback releases the read connection without detaching ORM
                # objects, so request context and tests remain consistent.
                db.session.rollback()
                record_login_succeeded(
                    user_id=user_id,
                    email=user_email,
                    auth_method=AUTH_METHOD_REGISTRATION,
                )
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
        if user is None:
            # Verify against a precomputed dummy hash so an unknown account is
            # not obviously cheaper than a known account.
            verify_dummy_password(form.password.data)
            # Release the read transaction before independent event storage.
            db.session.rollback()
            record_login_failed(
                identifier=form.email.data,
                reason=SECURITY_REASON_UNKNOWN_ACCOUNT,
            )
            flash("Invalid email or password.", "error")
        elif not user.is_active:
            verify_dummy_password(form.password.data)
            subject_user_id = user.id
            subject_email = user.email
            db.session.rollback()
            record_login_failed(
                identifier=form.email.data,
                reason=SECURITY_REASON_INACTIVE_ACCOUNT,
                subject_user_id=subject_user_id,
                subject_email=subject_email,
            )
            flash("Invalid email or password.", "error")
        elif not user.verify_password(form.password.data):
            subject_user_id = user.id
            subject_email = user.email
            db.session.rollback()
            record_login_failed(
                identifier=form.email.data,
                reason=SECURITY_REASON_INVALID_PASSWORD,
                subject_user_id=subject_user_id,
                subject_email=subject_email,
            )
            flash("Invalid email or password.", "error")
        else:
            user.last_login_at = datetime.now(UTC)
            user_id = user.id
            user_email = user.email
            db.session.commit()

            # Reload before releasing the read connection; login_user uses the
            # loaded object, and the event insert then runs with no other
            # request connection checked out.
            db.session.refresh(user)
            _clear_session()
            login_user(user, remember=form.remember.data)
            # The last-login commit is complete; rollback releases the read
            # connection without detaching ORM objects.
            db.session.rollback()
            record_login_succeeded(
                user_id=user_id,
                email=user_email,
                auth_method=AUTH_METHOD_PASSWORD,
                remember_requested=bool(form.remember.data),
            )
            flash("Signed in. Welcome back.", "success")
            destination = _safe_next_url(form.next.data) or url_for("storefront.home")
            return redirect(destination)

    return render_template("auth/login.html", form=form)


@auth_bp.post("/logout")
@login_required
def logout() -> ResponseReturnValue:
    """End the current session.  Logout is POST-only and CSRF protected."""
    # Capture identity before logout_user() turns current_user anonymous.
    user_id = current_user.id
    user_email = current_user.email
    logout_user()
    _clear_session()
    # Release the user_loader read transaction before event persistence.
    db.session.rollback()
    record_logout(user_id=user_id, email=user_email)
    flash("Signed out.", "info")
    return redirect(url_for("storefront.home"))


@auth_bp.get("/account")
@login_required
def account() -> ResponseReturnValue:
    """Show the signed-in user's own profile and avatar controls."""
    return _render_account()


@auth_bp.post("/account/profile")
@login_required
def profile_update() -> ResponseReturnValue:
    """Update only the signed-in user's full name and email."""
    form = ProfileForm()
    if form.validate_on_submit():
        try:
            update_profile(
                current_user.id,
                full_name=form.full_name.data,
                email=form.email.data,
            )
        except ProfileConflictError as exc:
            form.email.errors.append(str(exc))
        except ProfileValidationError as exc:
            flash(str(exc), "error")
        except ProfileError as exc:
            flash(str(exc), "error")
        else:
            flash("Profile updated.", "success")
            return redirect(url_for("auth.account"))

    return _render_account(profile_form=form)


@auth_bp.post("/account/avatar")
@login_required
def avatar_upload() -> ResponseReturnValue:
    """Validate and replace the signed-in user's private avatar."""
    form = AvatarUploadForm()
    if form.validate_on_submit():
        try:
            result = save_avatar(current_user.id, form.avatar.data)
        except AvatarValidationError as exc:
            form.avatar.errors.append(str(exc))
        except AvatarError as exc:
            flash(str(exc), "error")
        else:
            flash("Avatar updated.", "success")
            if result.cleanup_failed:
                flash("The previous avatar file could not be removed.", "info")
            return redirect(url_for("auth.account"))

    return _render_account(avatar_form=form)


@auth_bp.post("/account/avatar/delete")
@login_required
def avatar_delete() -> ResponseReturnValue:
    """Remove the signed-in user's avatar after a successful commit."""
    form = RemoveAvatarForm()
    if not form.validate_on_submit():
        flash("Avatar could not be removed.", "error")
        return redirect(url_for("auth.account"))

    try:
        result = remove_avatar(current_user.id)
    except AvatarError as exc:
        flash(str(exc), "error")
    else:
        if result.old_filename is None:
            flash("No avatar to remove.", "info")
        else:
            flash("Avatar removed. The default avatar is now active.", "success")
        if result.cleanup_failed:
            flash("The old avatar file could not be removed.", "info")

    return redirect(url_for("auth.account"))


@auth_bp.get("/avatar")
@login_required
def avatar() -> ResponseReturnValue:
    """Serve only the signed-in user's own private avatar."""
    filename = current_user.avatar_filename
    if not filename or not avatar_file_exists(filename):
        abort(404)

    try:
        path = avatar_file_path(filename)
        response = send_file(
            path,
            mimetype="image/webp",
            as_attachment=False,
            conditional=True,
            max_age=0,
        )
    except (AvatarError, OSError):
        abort(404)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store"
    return response
