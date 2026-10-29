"""Deterministic, idempotent catalog seed definitions and upserts."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Final

from sqlalchemy import select

from app.extensions import db
from app.models import Category, Product, ProductImage, ProductVariant


@dataclass(frozen=True, slots=True)
class CategorySeed:
    """A stable category definition used by the seed command."""

    name: str
    slug: str
    description: str
    icon: str
    position: int


@dataclass(frozen=True, slots=True)
class VariantSeed:
    """One size/colour inventory record."""

    size: str
    color: str
    sku: str
    stock: int


@dataclass(frozen=True, slots=True)
class ProductSeed:
    """A stable product definition and its initial inventory."""

    name: str
    slug: str
    category_slug: str
    description: str
    price: Decimal
    image_path: str
    image_alt: str
    badge: str | None
    variants: tuple[VariantSeed, ...]


@dataclass(frozen=True, slots=True)
class SeedSummary:
    """Counts produced by a seed run."""

    categories_created: int = 0
    categories_updated: int = 0
    products_created: int = 0
    products_updated: int = 0
    variants_created: int = 0
    variants_updated: int = 0
    images_created: int = 0
    images_updated: int = 0

    @property
    def created(self) -> int:
        """Total newly created catalog records."""
        return (
            self.categories_created
            + self.products_created
            + self.variants_created
            + self.images_created
        )

    @property
    def updated(self) -> int:
        """Total refreshed catalog records."""
        return (
            self.categories_updated
            + self.products_updated
            + self.variants_updated
            + self.images_updated
        )


CATEGORY_SEEDS: Final[tuple[CategorySeed, ...]] = (
    CategorySeed(
        name="T-shirts",
        slug="t-shirts",
        description="Heavyweight cotton. Oversized cuts. The daily uniform.",
        icon="images/category-tees.svg",
        position=10,
    ),
    CategorySeed(
        name="Hoodies",
        slug="hoodies",
        description="Brushed fleece and structured hoods built for low light.",
        icon="images/category-hoodies.svg",
        position=20,
    ),
    CategorySeed(
        name="Pants",
        slug="pants",
        description="Wide silhouettes, technical seams and an easy drape.",
        icon="images/category-pants.svg",
        position=30,
    ),
    CategorySeed(
        name="Accessories",
        slug="accessories",
        description="Caps and finishing pieces that complete the signal.",
        icon="images/category-accessories.svg",
        position=40,
    ),
)

PRODUCT_SEEDS: Final[tuple[ProductSeed, ...]] = (
    ProductSeed(
        name="Void Tee",
        slug="void-tee",
        category_slug="t-shirts",
        description=(
            "An oversized heavyweight tee in washed black, cut with a dropped "
            "shoulder and finished with a small acid-green chest mark. The "
            "cotton is garment-dyed so every piece settles into its own tone."
        ),
        price=Decimal("75.00"),
        image_path="images/product-void-tee.svg",
        image_alt="Oversized washed-black UTOP14 t-shirt with a small lime chest print.",
        badge="New",
        variants=(
            VariantSeed("S", "Washed Black", "UT014-VT-WBK-S", 12),
            VariantSeed("M", "Washed Black", "UT014-VT-WBK-M", 18),
            VariantSeed("L", "Washed Black", "UT014-VT-WBK-L", 9),
            VariantSeed("XL", "Washed Black", "UT014-VT-WBK-XL", 0),
        ),
    ),
    ProductSeed(
        name="Signal Hoodie",
        slug="signal-hoodie",
        category_slug="hoodies",
        description=(
            "A dense brushed-fleece hoodie with a structured double-layer hood "
            "and a wide body. The chest graphic carries the only hit of acid "
            "green in the collection."
        ),
        price=Decimal("180.00"),
        image_path="images/product-signal-hoodie.svg",
        image_alt="Heavyweight charcoal hoodie with a lime graphic across the chest.",
        badge="Drop 014",
        variants=(
            VariantSeed("XS", "Faded Charcoal", "UT014-SH-FCH-XS", 0),
            VariantSeed("S", "Faded Charcoal", "UT014-SH-FCH-S", 6),
            VariantSeed("M", "Faded Charcoal", "UT014-SH-FCH-M", 11),
            VariantSeed("L", "Faded Charcoal", "UT014-SH-FCH-L", 7),
            VariantSeed("XL", "Faded Charcoal", "UT014-SH-FCH-XL", 3),
        ),
    ),
    ProductSeed(
        name="Utility Pant",
        slug="utility-pant",
        category_slug="pants",
        description=(
            "A wide-leg utility trouser in storm grey with a gusseted crotch, "
            "articulated knee and a single technical pocket. Cut long so the "
            "hem stacks cleanly over boots."
        ),
        price=Decimal("160.00"),
        image_path="images/product-utility-pant.svg",
        image_alt="Wide-leg storm-grey utility trousers with a technical pocket.",
        badge=None,
        variants=(
            VariantSeed("28", "Storm Grey", "UT014-UP-STG-28", 4),
            VariantSeed("30", "Storm Grey", "UT014-UP-STG-30", 8),
            VariantSeed("32", "Storm Grey", "UT014-UP-STG-32", 6),
            VariantSeed("34", "Storm Grey", "UT014-UP-STG-34", 0),
        ),
    ),
    ProductSeed(
        name="Orbit Cap",
        slug="orbit-cap",
        category_slug="accessories",
        description=(
            "A six-panel structured cap in jet black with a curved brim, metal "
            "eyelets and a small embroidered UTOP14 mark. Adjustable at the back."
        ),
        price=Decimal("55.00"),
        image_path="images/product-orbit-cap.svg",
        image_alt="Structured black cap with a small lime embroidered UTOP14 mark.",
        badge=None,
        variants=(VariantSeed("One Size", "Jet Black", "UT014-OC-JBK-OS", 24),),
    ),
)


def seed_catalog() -> SeedSummary:
    """Create or refresh the launch catalog without deleting user data.

    Every record is matched by a stable natural key (category/product slug,
    variant size/colour and gallery position).  Re-running the command updates
    the same rows rather than inserting duplicates.
    """
    counts = {
        "categories_created": 0,
        "categories_updated": 0,
        "products_created": 0,
        "products_updated": 0,
        "variants_created": 0,
        "variants_updated": 0,
        "images_created": 0,
        "images_updated": 0,
    }
    categories: dict[str, Category] = {}

    try:
        for category_seed in CATEGORY_SEEDS:
            category = db.session.scalar(
                select(Category).where(Category.slug == category_seed.slug)
            )
            if category is None:
                category = Category(slug=category_seed.slug)
                db.session.add(category)
                counts["categories_created"] += 1
            else:
                counts["categories_updated"] += 1

            category.name = category_seed.name
            category.description = category_seed.description
            category.icon = category_seed.icon
            category.position = category_seed.position
            category.is_active = True
            categories[category_seed.slug] = category

        db.session.flush()

        for product_seed in PRODUCT_SEEDS:
            category = categories[product_seed.category_slug]
            product = db.session.scalar(select(Product).where(Product.slug == product_seed.slug))
            if product is None:
                product = Product(slug=product_seed.slug)
                db.session.add(product)
                counts["products_created"] += 1
            else:
                counts["products_updated"] += 1

            product.category = category
            product.name = product_seed.name
            product.description = product_seed.description
            product.price = product_seed.price
            product.image_path = product_seed.image_path
            product.image_alt = product_seed.image_alt
            product.badge = product_seed.badge
            product.is_active = True
            db.session.flush()

            for variant_seed in product_seed.variants:
                variant = db.session.scalar(
                    select(ProductVariant).where(
                        ProductVariant.product_id == product.id,
                        ProductVariant.size == variant_seed.size,
                        ProductVariant.color == variant_seed.color,
                    )
                )
                if variant is None:
                    variant = db.session.scalar(
                        select(ProductVariant).where(ProductVariant.sku == variant_seed.sku)
                    )
                if variant is None:
                    variant = ProductVariant(
                        product=product,
                        size=variant_seed.size,
                        color=variant_seed.color,
                        sku=variant_seed.sku,
                    )
                    db.session.add(variant)
                    counts["variants_created"] += 1
                else:
                    counts["variants_updated"] += 1

                variant.product = product
                variant.size = variant_seed.size
                variant.color = variant_seed.color
                variant.sku = variant_seed.sku
                variant.stock = variant_seed.stock
                variant.is_active = True

            image = db.session.scalar(
                select(ProductImage).where(
                    ProductImage.product_id == product.id,
                    ProductImage.position == 0,
                )
            )
            if image is None:
                image = ProductImage(product=product, position=0)
                db.session.add(image)
                counts["images_created"] += 1
            else:
                counts["images_updated"] += 1

            image.image_path = product_seed.image_path
            image.alt_text = product_seed.image_alt

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return SeedSummary(**counts)
