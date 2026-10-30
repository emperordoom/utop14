"""Unit tests for private avatar storage configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from app.config import PROJECT_ROOT, ConfigurationError


def test_avatar_defaults_are_private_and_bounded() -> None:
    app = create_app("testing")
    storage = Path(app.config["AVATAR_STORAGE_PATH"]).resolve()
    static_root = Path(app.static_folder).resolve()
    app_root = Path(app.root_path).resolve()

    assert app.config["AVATAR_MAX_BYTES"] == 2 * 1024 * 1024
    assert app.config["AVATAR_MAX_DIMENSION"] == 2048
    assert storage.is_absolute()
    assert storage != static_root
    assert static_root not in storage.parents
    assert storage != app_root
    assert app_root not in storage.parents


def test_configured_avatar_storage_outside_static_is_accepted(tmp_path: Path) -> None:
    storage = tmp_path / "private-avatars"
    app = create_app("testing", {"AVATAR_STORAGE_PATH": str(storage)})

    assert Path(app.config["AVATAR_STORAGE_PATH"]) == storage.resolve()


def test_avatar_storage_inside_source_tree_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="outside"):
        create_app(
            "testing",
            {"AVATAR_STORAGE_PATH": str(PROJECT_ROOT / "app" / "static" / "avatars")},
        )


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("AVATAR_MAX_BYTES", 0),
        ("AVATAR_MAX_BYTES", 2 * 1024 * 1024 + 1),
        ("AVATAR_MAX_DIMENSION", 32),
        ("AVATAR_MAX_DIMENSION", 4097),
    ],
)
def test_invalid_avatar_limits_are_rejected(key: str, value: int) -> None:
    with pytest.raises(ConfigurationError, match=key):
        create_app("testing", {key: value})
