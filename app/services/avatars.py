"""Secure avatar validation, storage and privacy-aware retrieval.

Uploaded files are decoded with Pillow, validated by content rather than by the
browser-supplied filename or MIME type, converted to a metadata-free WebP and
written atomically below a private storage directory outside the static tree.
Only the generated filename is persisted on the user row.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import uuid4

from flask import current_app
from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.datastructures import FileStorage

from app.extensions import db
from app.models import User

ALLOWED_FORMATS: Final = frozenset({"JPEG", "PNG", "WEBP"})
AVATAR_FILENAME_PATTERN: Final = re.compile(r"^[0-9a-f]{32}\.webp$")
MAX_IMAGE_PIXELS: Final = 16_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

_INVALID_IMAGE_MESSAGE = "Upload a valid JPEG, PNG or WebP image."


class AvatarError(Exception):
    """Base error for avatar operations that cannot be completed."""


class AvatarValidationError(AvatarError):
    """Raised when an uploaded avatar fails content or size validation."""


class AvatarStorageError(AvatarError):
    """Raised when an avatar file or database transaction cannot be completed."""


@dataclass(frozen=True, slots=True)
class AvatarUpdate:
    """The result of replacing a user's avatar."""

    user: User
    old_filename: str | None
    new_filename: str
    cleanup_failed: bool


@dataclass(frozen=True, slots=True)
class AvatarRemoval:
    """The result of removing a user's avatar."""

    old_filename: str | None
    cleanup_failed: bool


def avatar_storage_path() -> Path:
    """Return the configured private avatar storage directory."""
    configured = current_app.config.get("AVATAR_STORAGE_PATH") or ""
    return Path(str(configured)).expanduser().resolve()


def validate_avatar_filename(filename: object) -> str:
    """Return a generated avatar filename or raise a validation error."""
    if not isinstance(filename, str) or not AVATAR_FILENAME_PATTERN.fullmatch(filename):
        raise AvatarValidationError("Invalid avatar filename.")
    return filename


def avatar_file_path(filename: str) -> Path:
    """Resolve a stored filename without allowing traversal outside storage."""
    safe_name = validate_avatar_filename(filename)
    base = avatar_storage_path()
    candidate = (base / safe_name).resolve()
    if candidate.parent != base or candidate.is_symlink():
        raise AvatarValidationError("Invalid avatar filename.")
    return candidate


def avatar_file_exists(filename: str | None) -> bool:
    """Return whether a stored avatar file exists, treating bad names as absent."""
    if not filename:
        return False
    try:
        return avatar_file_path(filename).is_file()
    except AvatarValidationError:
        return False


def save_avatar(user_id: int, upload: FileStorage | None) -> AvatarUpdate:
    """Validate, store and attach a new avatar to one user.

    The new file is written first.  If the database transaction fails, the new
    file is removed and the previous avatar remains untouched.  The old file is
    deleted only after a successful commit.
    """
    filename, data = _encode_avatar(upload)
    _write_atomic(filename, data)

    try:
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise AvatarStorageError("Account could not be updated.")
        old_filename = user.avatar_filename
        user.avatar_filename = filename
        _commit_or_raise()
    except SQLAlchemyError as exc:
        db.session.rollback()
        _delete_file_quietly(filename)
        raise AvatarStorageError("Avatar could not be saved. Please try again.") from exc
    except Exception:
        db.session.rollback()
        _delete_file_quietly(filename)
        raise

    cleanup_failed = False
    if old_filename and old_filename != filename:
        try:
            delete_avatar_file(old_filename)
        except AvatarError:
            cleanup_failed = True

    return AvatarUpdate(
        user=user,
        old_filename=old_filename,
        new_filename=filename,
        cleanup_failed=cleanup_failed,
    )


def remove_avatar(user_id: int) -> AvatarRemoval:
    """Set a user's avatar to NULL, then remove the old file after commit."""
    try:
        user = db.session.scalar(select(User).where(User.id == user_id).with_for_update())
        if user is None:
            raise AvatarStorageError("Account could not be updated.")

        old_filename = user.avatar_filename
        if old_filename is None:
            return AvatarRemoval(old_filename=None, cleanup_failed=False)

        user.avatar_filename = None
        _commit_or_raise()
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise AvatarStorageError("Avatar could not be removed. Please try again.") from exc

    cleanup_failed = False
    try:
        delete_avatar_file(old_filename)
    except AvatarError:
        cleanup_failed = True

    return AvatarRemoval(old_filename=old_filename, cleanup_failed=cleanup_failed)


def delete_avatar_file(filename: str) -> bool:
    """Delete a generated avatar file, returning whether it existed."""
    path = avatar_file_path(filename)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AvatarStorageError("Avatar file could not be removed.") from exc
    return True


def _encode_avatar(upload: FileStorage | None) -> tuple[str, bytes]:
    """Validate upload content and return a generated filename and WebP bytes."""
    if not isinstance(upload, FileStorage):
        raise AvatarValidationError("Choose an image file.")

    max_bytes = int(current_app.config.get("AVATAR_MAX_BYTES", 2 * 1024 * 1024))
    max_dimension = int(current_app.config.get("AVATAR_MAX_DIMENSION", 2048))

    data = upload.stream.read(max_bytes + 1)
    if not data:
        raise AvatarValidationError("Choose a non-empty image file.")
    if len(data) > max_bytes:
        raise AvatarValidationError("Avatar exceeds the maximum file size.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                if probe.format not in ALLOWED_FORMATS:
                    raise AvatarValidationError(_INVALID_IMAGE_MESSAGE)
                probe.verify()

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format not in ALLOWED_FORMATS:
                    raise AvatarValidationError(_INVALID_IMAGE_MESSAGE)
                if getattr(image, "is_animated", False):
                    raise AvatarValidationError("Animated avatars are not supported.")

                width, height = image.size
                if width < 1 or height < 1:
                    raise AvatarValidationError(_INVALID_IMAGE_MESSAGE)
                if max(width, height) > max_dimension or width * height > max_dimension**2:
                    raise AvatarValidationError(
                        f"Avatar dimensions must not exceed {max_dimension} pixels."
                    )

                image.load()
                oriented = ImageOps.exif_transpose(image)
                has_alpha = oriented.mode in {"RGBA", "LA"} or (
                    oriented.mode == "P" and "transparency" in oriented.info
                )
                converted = Image.new(
                    "RGBA" if has_alpha else "RGB",
                    oriented.size,
                )
                converted.paste(oriented.convert(converted.mode))

                output = io.BytesIO()
                converted.save(output, format="WEBP", quality=90, method=6)
                encoded = output.getvalue()
    except AvatarValidationError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        UnidentifiedImageError,
        ValueError,
    ) as exc:
        raise AvatarValidationError(_INVALID_IMAGE_MESSAGE) from exc

    return f"{uuid4().hex}.webp", encoded


def _write_atomic(filename: str, data: bytes) -> None:
    """Write an avatar file atomically inside the private storage directory."""
    storage = avatar_storage_path()
    try:
        storage.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(storage, 0o700)
    except OSError as exc:
        raise AvatarStorageError("Avatar storage is not available.") from exc
    if not storage.is_dir():
        raise AvatarStorageError("Avatar storage is not available.")

    target = avatar_file_path(filename)
    temp_name: str | None = None
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".avatar-",
            suffix=".tmp",
            dir=storage,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, target)
        temp_name = None
    except OSError as exc:
        raise AvatarStorageError("Avatar could not be saved. Please try again.") from exc
    finally:
        if temp_name is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_name)


def _delete_file_quietly(filename: str) -> None:
    """Best-effort cleanup used when a database transaction fails."""
    with contextlib.suppress(AvatarError):
        delete_avatar_file(filename)


def _commit_or_raise() -> None:
    """Commit the avatar transaction and translate database failures."""
    try:
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        raise AvatarStorageError("Avatar could not be saved. Please try again.") from exc
