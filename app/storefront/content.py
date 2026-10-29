"""Editorial storefront content and shared display helpers.

Catalog records live in PostgreSQL and are read through ``app.services.catalog``.
Only campaign copy and formatting rules belong here so templates stay free of
database queries and presentation constants stay easy to update.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Final


@dataclass(frozen=True, slots=True)
class Collection:
    """Editorial content for the featured collection."""

    name: str
    chapter: str
    description: str
    image: str
    image_alt: str
    details: tuple[str, ...]


FEATURED_COLLECTION: Final[Collection] = Collection(
    name="After Hours",
    chapter="Chapter 014 / AW26",
    description=(
        "A study in low light. Washed blacks, storm greys and one electric "
        "signal of acid green, cut into pieces that move between the last "
        "train and the first morning."
    ),
    image="images/collection-after-hours.svg",
    image_alt="Two figures in charcoal streetwear standing beneath a lime light in a dark studio.",
    details=("12 pieces", "Heavyweight cotton", "Limited run"),
)


def format_money(value: Decimal) -> str:
    """Format a decimal amount using the storefront's editorial price style.

    Whole amounts are rendered without trailing zeroes (``$75``); fractional
    amounts keep two decimal places. Values must already be ``Decimal`` so
    callers cannot accidentally introduce binary floating-point rounding.
    """

    if not isinstance(value, Decimal):
        raise TypeError("format_money expects a Decimal value")

    if value == value.to_integral_value():
        return f"${value:,.0f}"
    return f"${value:,.2f}"
