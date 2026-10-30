"""Integration tests for secure avatar upload, storage and privacy."""

from __future__ import annotations

import io
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from PIL import Image

from app.extensions import db
from app.models import User
from app.services.avatars import AvatarStorageError

PASSWORD = "ValidPass123"
AVATAR_FILENAME = re.compile(r"^[0-9a-f]{32}\.webp$")


def _image_bytes(
    fmt: str = "PNG",
    *,
    size: tuple[int, int] = (64, 64),
    colour: str = "#7c3aed",
) -> bytes:
    image = Image.new("RGB", size, colour)
    output = io.BytesIO()
    image.save(output, format=fmt)
    return output.getvalue()


def _oriented_jpeg_bytes() -> bytes:
    image = Image.new("RGB", (40, 80), "#22c55e")
    exif = Image.Exif()
    exif[274] = 6
    output = io.BytesIO()
    image.save(output, format="JPEG", exif=exif)
    return output.getvalue()


def _animated_webp_bytes() -> bytes:
    frames = [
        Image.new("RGB", (32, 32), "#ef4444"),
        Image.new("RGB", (32, 32), "#3b82f6"),
    ]
    output = io.BytesIO()
    frames[0].save(
        output,
        format="WEBP",
        save_all=True,
        append_images=frames[1:],
        duration=100,
    )
    return output.getvalue()


def _upload_avatar(
    client: FlaskClient,
    token: str,
    payload: bytes,
    *,
    filename: str = "avatar.png",
    content_type: str = "image/png",
    include_csrf: bool = True,
    follow_redirects: bool = True,
) -> object:
    data: dict[str, object] = {
        "avatar": (io.BytesIO(payload), filename, content_type),
    }
    if include_csrf:
        data["csrf_token"] = token
    return client.post(
        "/auth/account/avatar",
        data=data,
        follow_redirects=follow_redirects,
    )


def _refresh_user(user: User) -> User:
    db.session.expire_all()
    refreshed = db.session.get(User, user.id)
    assert refreshed is not None
    return refreshed


def _stored_names(storage: Path) -> list[str]:
    return sorted(path.name for path in storage.iterdir()) if storage.exists() else []


def _logout(client: FlaskClient, token_for: Callable[[str], str]) -> None:
    response = client.post(
        "/auth/logout",
        data={"csrf_token": token_for("/auth/account")},
    )
    assert response.status_code == 302


@pytest.mark.parametrize(
    ("fmt", "filename"),
    [
        ("JPEG", "avatar.jpg"),
        ("PNG", "avatar.png"),
        ("WEBP", "avatar.webp"),
    ],
)
def test_avatar_upload_accepts_jpeg_png_and_webp(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
    fmt: str,
    filename: str,
) -> None:
    user = make_user(email=f"avatar-{fmt.lower()}@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_avatar(
        client,
        token,
        _image_bytes(fmt),
        filename=filename,
        content_type=f"image/{fmt.lower()}",
    )

    assert response.status_code == 200
    assert "Avatar updated." in response.get_data(as_text=True)

    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is not None
    assert AVATAR_FILENAME.fullmatch(refreshed.avatar_filename)
    stored_path = avatar_storage / refreshed.avatar_filename
    assert stored_path.is_file()
    assert stored_path.read_bytes().startswith(b"RIFF")
    assert stored_path.stat().st_mode & 0o777 == 0o600
    assert avatar_storage.stat().st_mode & 0o777 == 0o700

    avatar_response = client.get("/auth/avatar")
    assert avatar_response.status_code == 200
    assert avatar_response.mimetype == "image/webp"
    assert avatar_response.headers["X-Content-Type-Options"] == "nosniff"
    assert avatar_response.headers["Cache-Control"] == "private, no-store"
    assert avatar_response.data == stored_path.read_bytes()

    account_html = client.get("/auth/account").get_data(as_text=True)
    assert 'src="/auth/avatar"' in account_html
    assert "Remove your current avatar" in account_html
    assert "/static/js/account.js" in account_html


def test_avatar_rejects_file_over_configured_size_limit(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(app.config, "AVATAR_MAX_BYTES", 128)
    user = make_user(email="avatar-too-large@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_avatar(
        client,
        token,
        _image_bytes("PNG", size=(256, 256)),
    )

    assert response.status_code == 200
    assert "Avatar exceeds the maximum file size." in response.get_data(as_text=True)
    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is None
    assert _stored_names(avatar_storage) == []


@pytest.mark.parametrize(
    ("payload", "filename", "content_type"),
    [
        (b'<svg xmlns="http://www.w3.org/2000/svg"></svg>', "avatar.svg", "image/svg+xml"),
        (b"<html><body>not an image</body></html>", "avatar.jpg", "image/jpeg"),
        (b"MZ" + b"\x00" * 128, "avatar.png", "image/png"),
        (b"not a valid image", "avatar.webp", "image/webp"),
    ],
)
def test_avatar_rejects_invalid_content_and_mime_spoofing(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
    payload: bytes,
    filename: str,
    content_type: str,
) -> None:
    user = make_user(email=f"avatar-invalid-{filename.replace('.', '-')}@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_avatar(
        client,
        token,
        payload,
        filename=filename,
        content_type=content_type,
    )

    assert response.status_code == 200
    assert "Upload a valid JPEG, PNG or WebP image." in response.get_data(as_text=True)
    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is None
    assert _stored_names(avatar_storage) == []


def test_avatar_rejects_animated_images(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-animated@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_avatar(
        client,
        token,
        _animated_webp_bytes(),
        filename="animated.webp",
        content_type="image/webp",
    )

    assert response.status_code == 200
    assert "Animated avatars are not supported." in response.get_data(as_text=True)
    assert _refresh_user(user).avatar_filename is None
    assert _stored_names(avatar_storage) == []


def test_avatar_uses_generated_filename_and_ignores_original_path(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-traversal@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    response = _upload_avatar(
        client,
        token,
        _image_bytes("PNG"),
        filename="../../evil.png",
    )

    assert response.status_code == 200
    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is not None
    assert AVATAR_FILENAME.fullmatch(refreshed.avatar_filename)
    assert "evil" not in refreshed.avatar_filename
    assert (avatar_storage / refreshed.avatar_filename).is_file()
    assert not (avatar_storage.parent / "evil.png").exists()


def test_avatar_replacement_removes_old_file(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-replace@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    _upload_avatar(client, token, _image_bytes("PNG"), filename="first.png")
    first = _refresh_user(user)
    assert first.avatar_filename is not None
    first_filename = first.avatar_filename
    first_path = avatar_storage / first_filename
    assert first_path.is_file()

    _upload_avatar(client, token, _image_bytes("JPEG"), filename="second.jpg")
    second = _refresh_user(user)
    assert second.avatar_filename is not None
    second_path = avatar_storage / second.avatar_filename
    assert second.avatar_filename != first_filename
    assert second_path.is_file()
    assert not first_path.exists()


def test_avatar_database_failure_keeps_old_file_and_removes_new_file(
    app: Flask,
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(email="avatar-db-failure@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    _upload_avatar(client, token, _image_bytes("PNG"), filename="first.png")
    first = _refresh_user(user)
    assert first.avatar_filename is not None
    first_path = avatar_storage / first.avatar_filename
    assert first_path.is_file()

    def _fail_commit() -> None:
        raise AvatarStorageError("Simulated database failure.")

    monkeypatch.setattr("app.services.avatars._commit_or_raise", _fail_commit)
    response = _upload_avatar(
        client,
        token,
        _image_bytes("JPEG"),
        filename="second.jpg",
    )

    assert response.status_code == 200
    assert "Simulated database failure." in response.get_data(as_text=True)
    db.session.rollback()
    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename == first.avatar_filename
    assert first_path.is_file()
    assert _stored_names(avatar_storage) == [first.avatar_filename]


def test_avatar_delete_restores_default_and_removes_file(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-delete@example.com", full_name="Test Customer")
    login(user.email)
    token = csrf_token("/auth/account")
    _upload_avatar(client, token, _image_bytes("PNG"))
    uploaded = _refresh_user(user)
    assert uploaded.avatar_filename is not None
    uploaded_path = avatar_storage / uploaded.avatar_filename

    response = client.post(
        "/auth/account/avatar/delete",
        data={"csrf_token": token},
        follow_redirects=True,
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Avatar removed. The default avatar is now active." in html
    assert "TC" in html
    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is None
    assert not uploaded_path.exists()
    assert client.get("/auth/avatar").status_code == 404


def test_avatar_delete_requires_csrf(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-delete-csrf@example.com")
    login(user.email)
    token = csrf_token("/auth/account")
    _upload_avatar(client, token, _image_bytes("PNG"))
    uploaded = _refresh_user(user)
    assert uploaded.avatar_filename is not None
    uploaded_path = avatar_storage / uploaded.avatar_filename

    response = client.post("/auth/account/avatar/delete", data={})

    assert response.status_code == 400
    assert uploaded_path.is_file()
    assert _refresh_user(user).avatar_filename == uploaded.avatar_filename


def test_avatar_upload_requires_csrf(
    client: FlaskClient,
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-upload-csrf@example.com")
    login(user.email)

    response = _upload_avatar(
        client,
        "",
        _image_bytes("PNG"),
        include_csrf=False,
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert _refresh_user(user).avatar_filename is None
    assert _stored_names(avatar_storage) == []


def test_missing_avatar_file_does_not_break_account_page(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-missing@example.com", full_name="Test Customer")
    login(user.email)
    token = csrf_token("/auth/account")
    _upload_avatar(client, token, _image_bytes("PNG"))
    uploaded = _refresh_user(user)
    assert uploaded.avatar_filename is not None
    (avatar_storage / uploaded.avatar_filename).unlink()

    assert client.get("/auth/avatar").status_code == 404
    response = client.get("/auth/account")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "stored avatar file is missing" in html
    assert "TC" in html


def test_avatar_is_private_to_current_user(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    owner = make_user(email="avatar-owner@example.com")
    other = make_user(email="avatar-other@example.com")
    login(owner.email)
    token = csrf_token("/auth/account")
    _upload_avatar(client, token, _image_bytes("PNG"))
    uploaded = _refresh_user(owner)
    assert uploaded.avatar_filename is not None
    owner_path = avatar_storage / uploaded.avatar_filename
    owner_bytes = owner_path.read_bytes()

    _logout(client, csrf_token)
    login(other.email)
    assert client.get("/auth/avatar").status_code == 404
    assert client.get("/auth/avatar/../../etc/passwd").status_code == 404

    _logout(client, csrf_token)
    login(owner.email)
    query_response = client.get("/auth/avatar?filename=../../etc/passwd")
    assert query_response.status_code == 200
    assert query_response.data == owner_bytes
    assert owner_path.is_file()


def test_avatar_upload_normalizes_exif_orientation_and_strips_metadata(
    client: FlaskClient,
    csrf_token: Callable[[str], str],
    login: Callable[..., object],
    make_user: Callable[..., User],
    avatar_storage: Path,
) -> None:
    user = make_user(email="avatar-orientation@example.com")
    login(user.email)
    token = csrf_token("/auth/account")

    _upload_avatar(
        client,
        token,
        _oriented_jpeg_bytes(),
        filename="portrait.jpg",
        content_type="image/jpeg",
    )

    refreshed = _refresh_user(user)
    assert refreshed.avatar_filename is not None
    stored_path = avatar_storage / refreshed.avatar_filename
    with Image.open(stored_path) as stored:
        assert stored.size == (80, 40)
        assert stored.getexif() == {}
