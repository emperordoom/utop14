"""UTOP14 Flask application factory."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from typing import Any

from flask import Flask

from app.config import get_config, load_environment, validate_config
from app.extensions import csrf, db, login_manager, migrate

__all__ = ["create_app"]


def create_app(
    config_name: str | None = None,
    config_overrides: Mapping[str, Any] | None = None,
) -> Flask:
    """Create and configure a Flask application instance.

    Args:
        config_name: ``development``, ``production`` or ``testing``.  When
            omitted, ``APP_ENV`` is used and defaults to ``development``.
        config_overrides: Optional values applied after environment-based
            configuration; primarily useful for tests and controlled
            deployment settings.

    Returns:
        A fully initialized Flask application.

    Raises:
        ConfigurationError: If required or unsafe configuration is detected.
    """
    load_environment()

    app = Flask(__name__, instance_relative_config=True)
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    app.config.update(config_class.load())

    if config_overrides:
        app.config.update(config_overrides)

    # Validate before initializing extensions so broken deployments stop
    # immediately and no component starts with an incomplete configuration.
    validate_config(app)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    _register_blueprints(app)
    _register_models()

    return app


def _register_blueprints(app: Flask) -> None:
    """Register application blueprints."""
    from app.main import main_bp

    app.register_blueprint(main_bp)


def _register_models() -> None:
    """Import the models package so Alembic can discover all mapped tables.

    ``app.models`` is the single registry for model modules.  Importing it in
    the factory keeps Flask-Migrate autogeneration migration-compatible while
    avoiding automatic table creation at application startup.
    """
    import_module("app.models")
