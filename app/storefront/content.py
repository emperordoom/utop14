"""Static storefront content for the UTOP14 homepage.

The milestone intentionally uses mock content rather than database models.
Keeping the presentation data here means the route stays thin and the same
records can later be replaced by catalog queries without rewriting templates.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Final


@dataclass(frozen=True, slots=True)
class Product:
    """A product card shown on the storefront."""

    name: str
    category: str
    price: Decimal
    colour: str
    image: str
    image_alt: str
    badge: str | None = None


@dataclass(frozen=True, slots=True)
class Category:
    """A top-level shopping category."""

    name: str
    description: str
    icon: str
    href: str


@dataclass(frozen=True, slots=True)
class Collection:
    """Editorial content for the featured collection."""

    name: str
    chapter: str
    description: str
    image: str
    image_alt: str
    details: tuple[str, ...]


PRODUCTS: Final[tuple[Product, ...]] = (
    Product(
        name="Void Tee",
        category="T-Shirt",
        price=Decimal("75.00"),
        colour="Washed Black",
        image="images/product-void-tee.svg",
        image_alt="Oversized washed-black UTOP14 t-shirt with a small lime chest print.",
        badge="New",
    ),
    Product(
        name="Signal Hoodie",
        category="Hoodie",
        price=Decimal("180.00"),
        colour="Faded Charcoal",
        image="images/product-signal-hoodie.svg",
        image_alt="Heavyweight charcoal hoodie with a lime graphic across the chest.",
        badge="Drop 014",
    ),
    Product(
        name="Utility Pant",
        category="Pants",
        price=Decimal("160.00"),
        colour="Storm Grey",
        image="images/product-utility-pant.svg",
        image_alt="Wide-leg storm-grey utility trousers with a technical pocket.",
    ),
    Product(
        name="Orbit Cap",
        category="Accessories",
        price=Decimal("55.00"),
        colour="Jet Black",
        image="images/product-orbit-cap.svg",
        image_alt="Structured black cap with a small lime embroidered UTOP14 mark.",
    ),
)

CATEGORIES: Final[tuple[Category, ...]] = (
    Category(
        name="T-shirts",
        description="Heavyweight cotton. Oversized cuts. The daily uniform.",
        icon="images/category-tees.svg",
        href="#featured",
    ),
    Category(
        name="Hoodies",
        description="Brushed fleece and structured hoods built for low light.",
        icon="images/category-hoodies.svg",
        href="#featured",
    ),
    Category(
        name="Pants",
        description="Wide silhouettes, technical seams and an easy drape.",
        icon="images/category-pants.svg",
        href="#featured",
    ),
    Category(
        name="Accessories",
        description="Caps and finishing pieces that complete the signal.",
        icon="images/category-accessories.svg",
        href="#featured",
    ),
)

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
