"""Secure private storage for manual bank-transfer evidence.

Evidence is validated by content, stored outside the web root under a
UUID-generated filename and preserved byte-for-byte after validation.  Images
are never re-encoded because they are review evidence, not decorative avatars.
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
from PIL import Image, UnidentifiedImageError
from werkzeug.datastructures import FileStorage

PROOF_FILENAME_PATTERN: Final = re.compile(r"^[0-9a-f]{32}\.(jpg|png|webp|pdf)$")
_IMAGE_FORMATS: Final = {
    "JPEG": ("image/jpeg", ".jpg"),
    "PNG": ("image/png", ".png"),
    "WEBP": ("image/webp", ".webp"),
}
_PDF_MIME: Final = "application/pdf"
PROOF_MIME_TYPES: Final = frozenset({"image/jpeg", "image/png", "image/webp", _PDF_MIME})
MAX_IMAGE_PIXELS: Final = 16_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

_INVALID_MESSAGE = "Upload a valid JPEG, PNG, WebP or PDF payment proof."


class ProofStorageError(Exception):
    """Base error for proof file validation and storage."""


class ProofValidationError(ProofStorageError):
    """Raised when uploaded evidence fails content or size validation."""


class ProofFileError(ProofStorageError):
    """Raised when evidence cannot be safely stored or removed."""


@dataclass(frozen=True, slots=True)
class PreparedProof:
    """A validated proof ready to be written atomically."""

    filename: str
    mime_type: str
    file_size: int
    data: bytes


def proof_storage_path() -> Path:
    """Return the configured private payment-proof directory."""
    configured = current_app.config.get("PAYMENT_PROOF_STORAGE_PATH") or ""
    return Path(str(configured)).expanduser().resolve()


def validate_proof_filename(filename: object) -> str:
    """Return a generated proof filename or raise a validation error."""
    if not isinstance(filename, str) or not PROOF_FILENAME_PATTERN.fullmatch(filename):
        raise ProofValidationError("Invalid payment proof filename.")
    return filename


def proof_file_path(filename: str) -> Path:
    """Resolve a stored proof filename without allowing path traversal."""
    safe_name = validate_proof_filename(filename)
    base = proof_storage_path()
    candidate = (base / safe_name).resolve()
    if candidate.parent != base or candidate.is_symlink():
        raise ProofValidationError("Invalid payment proof filename.")
    return candidate


def proof_file_exists(filename: str | None) -> bool:
    """Return whether stored evidence exists, treating invalid names as absent."""
    if not filename:
        return False
    try:
        return proof_file_path(filename).is_file()
    except ProofValidationError:
        return False


def prepare_proof_upload(upload: FileStorage | None) -> PreparedProof:
    """Validate upload content and return an unmodified prepared proof."""
    if not isinstance(upload, FileStorage):
        raise ProofValidationError("Choose a payment proof file.")

    max_bytes = int(current_app.config.get("PAYMENT_PROOF_MAX_BYTES", 5 * 1024 * 1024))
    max_dimension = int(current_app.config.get("PAYMENT_PROOF_MAX_DIMENSION", 4096))

    data = upload.stream.read(max_bytes + 1)
    if not data:
        raise ProofValidationError("Choose a non-empty payment proof file.")
    if len(data) > max_bytes:
        raise ProofValidationError("Payment proof exceeds the maximum file size.")

    if data.startswith(b"%PDF-"):
        _validate_pdf(data)
        return PreparedProof(
            filename=f"{uuid4().hex}.pdf",
            mime_type=_PDF_MIME,
            file_size=len(data),
            data=data,
        )

    mime_type, suffix = _validate_image(data, max_dimension)
    return PreparedProof(
        filename=f"{uuid4().hex}{suffix}",
        mime_type=mime_type,
        file_size=len(data),
        data=data,
    )


def store_proof_file(prepared: PreparedProof) -> Path:
    """Write validated evidence atomically into private storage."""
    storage = proof_storage_path()
    try:
        storage.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(storage, 0o700)
    except OSError as exc:
        raise ProofFileError("Payment proof storage is not available.") from exc
    if not storage.is_dir():
        raise ProofFileError("Payment proof storage is not available.")

    target = proof_file_path(prepared.filename)
    temp_name: str | None = None
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".proof-",
            suffix=".tmp",
            dir=storage,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(prepared.data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, target)
        temp_name = None
    except OSError as exc:
        raise ProofFileError("Payment proof could not be saved.") from exc
    finally:
        if temp_name is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_name)
    return target


def delete_proof_file(filename: str) -> bool:
    """Delete a generated proof file, returning whether it existed."""
    path = proof_file_path(filename)
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ProofFileError("Payment proof file could not be removed.") from exc
    return True


def _validate_image(data: bytes, max_dimension: int) -> tuple[str, str]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                image_format = probe.format
                if image_format not in _IMAGE_FORMATS:
                    raise ProofValidationError(_INVALID_MESSAGE)
                probe.verify()

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.format not in _IMAGE_FORMATS:
                    raise ProofValidationError(_INVALID_MESSAGE)
                if getattr(image, "is_animated", False):
                    raise ProofValidationError("Animated proof images are not supported.")
                width, height = image.size
                if width < 1 or height < 1:
                    raise ProofValidationError(_INVALID_MESSAGE)
                if max(width, height) > max_dimension or width * height > MAX_IMAGE_PIXELS:
                    raise ProofValidationError(
                        f"Proof image dimensions must not exceed {max_dimension} pixels."
                    )
                image.load()
    except ProofValidationError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        UnidentifiedImageError,
        ValueError,
    ) as exc:
        raise ProofValidationError(_INVALID_MESSAGE) from exc

    return _IMAGE_FORMATS[image_format]


def _validate_pdf(data: bytes) -> None:
    """Apply a conservative structural check without rendering the PDF."""
    if len(data) < 32:
        raise ProofValidationError(_INVALID_MESSAGE)
    if b"%%EOF" not in data[-2048:]:
        raise ProofValidationError(_INVALID_MESSAGE)
    if b"startxref" not in data[-8192:]:
        raise ProofValidationError(_INVALID_MESSAGE)
    if b"obj" not in data:
        raise ProofValidationError(_INVALID_MESSAGE)
