"""Integration tests for the health endpoint."""

from __future__ import annotations

from flask import Flask
from flask.testing import FlaskClient


def test_health_endpoint_returns_ok(client: FlaskClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.is_json
    assert response.get_json() == {"status": "ok"}


def test_health_endpoint_does_not_expose_configuration(
    client: FlaskClient,
    app: Flask,
) -> None:
    response = client.get("/health")
    body = response.get_data(as_text=True).lower()

    for forbidden in ("secret", "database", "postgres", "password", "session"):
        assert forbidden not in body

    assert str(app.config["SECRET_KEY"]).lower() not in body
