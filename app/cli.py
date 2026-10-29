"""Flask CLI commands for local catalog maintenance."""

from __future__ import annotations

import click

from app.catalog.seed import seed_catalog


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
