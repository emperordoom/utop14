"""Flask CLI commands for catalog and account maintenance."""

from __future__ import annotations

import click
from email_validator import EmailNotValidError, validate_email
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.catalog.seed import seed_catalog
from app.extensions import db
from app.models.user import ROLE_ADMIN, User
from app.services.auth_rate_limit import RateLimitStoreError, delete_expired_buckets


@click.group("catalog")
def catalog_cli() -> None:
    """Catalog maintenance commands."""


@catalog_cli.command("seed")
def seed_command() -> None:
    """Create or refresh the deterministic launch catalog.

    The command is idempotent and never deletes catalog records.  Re-running it
    updates rows matched by stable natural keys instead of inserting duplicates.
    """
    summary = seed_catalog()
    click.echo(
        "Catalog seeded: "
        f"{summary.categories_created} categories, "
        f"{summary.products_created} products, "
        f"{summary.variants_created} variants and "
        f"{summary.images_created} images created; "
        f"{summary.updated} existing records refreshed."
    )


@click.group("users")
def users_cli() -> None:
    """Account provisioning commands."""


@users_cli.command("create-admin")
def create_admin_command() -> None:
    """Provision the initial admin account through a secure interactive prompt.

    Passwords are collected with hidden input and are never echoed, logged or
    accepted as command-line arguments.  The command refuses to create a second
    admin account or to reuse an existing email address.
    """
    existing_admin = db.session.scalar(select(User).where(User.role == ROLE_ADMIN).limit(1))
    if existing_admin is not None:
        raise click.ClickException("An admin account already exists.")

    raw_email = click.prompt("Email", type=str)
    try:
        email = validate_email(raw_email.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError as exc:
        raise click.ClickException("Enter a valid email address.") from exc

    if db.session.scalar(select(User).where(User.email == email)) is not None:
        raise click.ClickException("An account with that email already exists.")

    full_name = click.prompt("Full name", default="UTOP14 Admin").strip()
    if not full_name or len(full_name) > 120:
        raise click.ClickException("Full name must be between 1 and 120 characters.")

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not password.strip() or len(password) < 8 or len(password) > 128:
        raise click.ClickException("Password must be between 8 and 128 characters.")

    user = User(
        email=email,
        full_name=full_name,
        role=ROLE_ADMIN,
        is_active=True,
    )
    user.set_password(password)
    db.session.add(user)

    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise click.ClickException("Unable to create the admin account.") from exc

    click.echo(f"Admin account created for {email}.")


@click.group("auth-rate-limit")
def auth_rate_limit_cli() -> None:
    """Authentication rate-limit maintenance commands."""


@auth_rate_limit_cli.command("cleanup")
@click.option(
    "--batch-size",
    type=click.IntRange(1, 5000),
    default=1000,
    show_default=True,
    help="Maximum number of expired buckets to delete in this invocation.",
)
def cleanup_rate_limits_command(batch_size: int) -> None:
    """Delete one bounded batch of expired authentication rate-limit buckets."""
    try:
        deleted = delete_expired_buckets(batch_size=batch_size)
    except RateLimitStoreError as exc:
        raise click.ClickException("Rate-limit cleanup failed.") from exc
    click.echo(f"Deleted {deleted} expired authentication rate-limit bucket(s).")
