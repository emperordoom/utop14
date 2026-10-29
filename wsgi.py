"""WSGI entry point for production application servers."""

from __future__ import annotations

from app import create_app

app = create_app()

__all__ = ["app"]
