"""SQLAlchemy model registry.

Import every model module here as it is added so Flask-Migrate/Alembic can
discover the complete metadata during ``flask db migrate``.  The application
factory imports this package on every startup; it never creates tables.

Future example::

    from app.models.product import Product  # noqa: F401
"""

from __future__ import annotations

__all__: list[str] = []
