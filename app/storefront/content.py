"""Editorial storefront content."""

from __future__ import annotations

from dataclasses import dataclass
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
