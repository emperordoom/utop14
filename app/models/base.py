"""Shared SQLAlchemy declarative base, timestamps and validators."""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePosixPath

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.extensions import db


class Base(db.Model):  # type: ignore[misc, name-defined]
    """Declarative base registered with Flask-SQLAlchemy's metadata."""

    __abstract__ = True


class TimestampMixin:
    """Add timezone-aware creation and update timestamps to a model."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


def validate_image_path(value: str) -> str:
    """Return a safe, relative image path or raise ``ValueError``.

    Catalog image paths are stored relative to ``app/static``.  Only paths
    directly beneath the ``images/`` directory are accepted, which prevents
    absolute paths, Windows separators and ``..`` traversal from reaching the
    filesystem when a template renders them through ``url_for('static')``.
    """

    if not isinstance(value, str):
        raise ValueError("image_path must be a string.")

    cleaned = value.strip()
    if not cleaned:
        raise ValueError("image_path must not be empty.")

    if cleaned.startswith(("/", "\\")) or "\\" in cleaned:
        raise ValueError("image_path must be a relative POSIX path.")

    raw_parts = cleaned.split("/")
    if any(part in {".", ".."} for part in raw_parts):
        raise ValueError("image_path must not contain traversal segments.")
    if any(not part for part in raw_parts):
        raise ValueError("image_path must not contain empty segments.")

    path = PurePosixPath(cleaned)
    parts = path.parts
    if len(parts) < 2 or parts[0] != "images":
        raise ValueError("image_path must live under the images/ directory.")

    return cleaned
