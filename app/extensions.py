"""Shared Flask extension instances.

Extensions live in their own module so the application factory, models and
blueprints can import them without creating circular dependencies.
"""

from __future__ import annotations

from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

# Harden Flask-Login sessions immediately.  The login view is intentionally
# configured with the authentication blueprint in a later milestone.
login_manager.session_protection = "strong"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"
