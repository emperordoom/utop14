"""Unit tests for profile normalization and avatar filename policy."""

from __future__ import annotations

import pytest

from app.services.avatars import (
    AvatarValidationError,
    validate_avatar_filename,
)
from app.services.profiles import (
    ProfileValidationError,
    normalize_full_name,
    normalize_profile_email,
)


def test_full_name_is_whitespace_normalized() -> None:
    assert normalize_full_name("  Ada   Byron   Lovelace  ") == "Ada Byron Lovelace"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_empty_full_name_is_rejected(value: str) -> None:
    with pytest.raises(ProfileValidationError, match="required"):
        normalize_full_name(value)


def test_too_long_full_name_is_rejected() -> None:
    with pytest.raises(ProfileValidationError, match="120"):
        normalize_full_name("A" * 121)


def test_email_is_lowercased_and_trimmed() -> None:
    assert normalize_profile_email("  Ada.Lovelace@Example.COM ") == "ada.lovelace@example.com"


@pytest.mark.parametrize("value", ["", "not-an-email", "missing-at-sign"])
def test_invalid_profile_email_is_rejected(value: str) -> None:
    with pytest.raises(ProfileValidationError, match="valid email"):
        normalize_profile_email(value)


def test_generated_avatar_filename_is_accepted() -> None:
    filename = f"{'a' * 32}.webp"
    assert validate_avatar_filename(filename) == filename


@pytest.mark.parametrize(
    "filename",
    [
        "../avatar.webp",
        f"{'a' * 32}.png",
        f"{'a' * 31}.webp",
        f"{'a' * 32}.webp/../escape.webp",
        "",
        None,
        123,
    ],
)
def test_unsafe_avatar_filename_is_rejected(filename: object) -> None:
    with pytest.raises(AvatarValidationError, match="Invalid avatar filename"):
        validate_avatar_filename(filename)
