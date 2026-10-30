"""UTOP14 Flask application factory."""

from __future__ import annotations

from collections.abc import Mapping
from importlib import import_module
from typing import Any

from flask import Flask, render_template

from app.config import (
    configure_avatar_storage,
    get_config,
    load_environment,
    validate_config,
)
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

    configure_avatar_storage(app)

    # Validate before initializing extensions so broken deployments stop
    # immediately and no component starts with an incomplete configuration.
    validate_config(app)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    _register_blueprints(app)
    _register_models()
    _register_cli(app)
    _register_error_handlers(app)

    return app


def _register_blueprints(app: Flask) -> None:
    """Register application blueprints."""
    from app.admin import admin_bp
    from app.auth import auth_bp
    from app.cart import cart_bp
    from app.checkout import checkout_bp
    from app.main import main_bp
    from app.orders import orders_bp
    from app.payments import payments_bp
    from app.payments import routes as _payment_routes  # noqa: F401
    from app.storefront import storefront_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(storefront_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(checkout_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(payments_bp)


def _register_models() -> None:
    """Import the models package so Alembic can discover all mapped tables.

    ``app.models`` is the single registry for model modules.  Importing it in
    the factory keeps Flask-Migrate autogeneration migration-compatible while
    avoiding automatic table creation at application startup.
    """
    import_module("app.models")


def _register_cli(app: Flask) -> None:
    """Attach maintenance commands without importing them at module load time."""
    from app.cli import catalog_cli, users_cli

    app.cli.add_command(catalog_cli)
    app.cli.add_command(users_cli)


def _register_error_handlers(app: Flask) -> None:
    """Render public errors with the storefront shell instead of Flask's default."""

    def forbidden(_error: Exception) -> tuple[str, int]:
        return render_template("errors/403.html"), 403

    def not_found(_error: Exception) -> tuple[str, int]:
        return render_template("errors/404.html"), 404

    app.register_error_handler(403, forbidden)
    app.register_error_handler(404, not_found)
