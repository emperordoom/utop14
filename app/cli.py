"""Flask CLI commands for catalog and account maintenance."""

from __future__ import annotations

import click
from email_validator import EmailNotValidError, validate_email
from flask import current_app
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError

from app.catalog.seed import seed_catalog
from app.extensions import db
from app.models.user import ROLE_ADMIN, User
from app.services.auth_rate_limit import RateLimitStoreError, delete_expired_buckets
from app.services.clock_skew import check_clock_skew
from app.services.security_event_filter_state import (
    FilterStateError,
    cleanup_expired_filter_states,
)
from app.services.security_event_retention import (
    RetentionLocked,
    RetentionRunError,
    RetentionValidationError,
    find_orphan_started_runs,
    run_retention,
)


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


@click.group("security-event-retention")
def security_event_retention_cli() -> None:
    """Security-event retention maintenance commands."""


def _retention_engine():
    database_url = str(
        current_app.config.get("SECURITY_EVENT_RETENTION_DATABASE_URL") or ""
    ).strip()
    if not database_url:
        raise click.ClickException(
            "SECURITY_EVENT_RETENTION_DATABASE_URL is required for retention runs."
        )
    return create_engine(database_url, pool_pre_ping=True)


@security_event_retention_cli.command("check-clock")
def check_clock_command() -> None:
    """Report application/database clock skew without failing the process.

    The diagnostic is advisory.  A missing or unreachable database, or a skew
    above ``CLOCK_SKEW_WARNING_SECONDS``, is reported as a warning and does not
    change the command's successful exit status.
    """
    result = check_clock_skew(db.engine)
    if result is None:
        click.echo(
            "Clock-skew diagnostic unavailable; no application request was failed.",
            err=True,
        )
        return
    click.echo(f"Clock skew: {result.skew_seconds:.1f}s (threshold {result.threshold_seconds}s).")
    if result.exceeded:
        click.echo(
            "WARNING: application and database clocks differ by more than the "
            "configured threshold.",
            err=True,
        )


@security_event_retention_cli.command("orphans")
@click.option(
    "--older-than-minutes",
    type=click.IntRange(1, 525600),
    default=60,
    show_default=True,
    help="Only report started rows older than this many minutes.",
)
def orphaned_runs_command(older_than_minutes: int) -> None:
    """List abandoned ``started`` run-log rows for monitoring."""
    engine = _retention_engine()
    try:
        rows = find_orphan_started_runs(
            engine,
            older_than_seconds=older_than_minutes * 60,
        )
    except RetentionValidationError as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive CLI boundary
        raise click.ClickException("Unable to read retention run-log state.") from exc
    finally:
        engine.dispose()

    if not rows:
        click.echo("No orphaned started retention runs.")
        return
    for row in rows:
        click.echo(
            f"started run_id={row.run_id} batch={row.batch_index} "
            f"scope={row.scope} executed_by={row.executed_by} "
            f"started_at={row.started_at.isoformat()}"
        )


@security_event_retention_cli.command("run")
@click.option(
    "--batch-size",
    type=click.IntRange(1, 5000),
    default=None,
    help="Rows per batch; defaults to configured value.",
)
@click.option(
    "--max-batches",
    type=click.IntRange(1, 100),
    default=None,
    help="Maximum batches in this run; defaults to configured value.",
)
def run_security_event_retention_command(
    batch_size: int | None,
    max_batches: int | None,
) -> None:
    """Run bounded security-event retention using the dedicated runner DSN."""
    if not current_app.config.get("SECURITY_EVENT_RETENTION_ENABLED", True):
        raise click.ClickException("Security-event retention is disabled.")

    # Advisory diagnostic only; never fail the run because of clock skew or an
    # unavailable diagnostic connection.
    check_clock_skew(db.engine)

    engine = _retention_engine()
    try:
        try:
            summary = run_retention(
                engine,
                batch_size=batch_size,
                max_batches=max_batches,
            )
        except RetentionLocked as exc:
            click.echo("Security-event retention is already running.", err=True)
            raise click.exceptions.Exit(3) from exc
        except (RetentionValidationError, RetentionRunError) as exc:
            raise click.ClickException(str(exc)) from exc
    finally:
        engine.dispose()

    click.echo(
        f"Retention {summary.status}: deleted={summary.deleted_count} "
        f"batches={summary.batch_count} run_id={summary.run_id}"
    )
    if summary.status == "partial":
        raise click.exceptions.Exit(2)


@click.group("admin-security-event-filters")
def admin_security_event_filters_cli() -> None:
    """Admin security-event filter-state maintenance commands."""


@admin_security_event_filters_cli.command("cleanup")
@click.option("--limit", type=int, default=1000, show_default=True)
def cleanup_filter_states_command(limit: int) -> None:
    """Delete expired server-side admin filter states in bounded batches.

    Security does not depend on this job: expired states are rejected at lookup
    time.  Run it from an operational scheduler as a follow-up.
    """
    if not 1 <= limit <= 10_000:
        raise click.ClickException("--limit must be between 1 and 10000.")
    try:
        deleted = cleanup_expired_filter_states(limit=limit)
    except FilterStateError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Deleted {deleted} expired security-event filter state(s).")
