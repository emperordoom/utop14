"""Shared pytest fixtures for UTOP14."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app


@pytest.fixture()
def app() -> Iterator[Flask]:
    """Create an application using deterministic, isolated test settings."""
    application = create_app("testing")
    yield application


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return a test client bound to the test application."""
    return app.test_client()
