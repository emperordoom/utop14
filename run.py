"""Local development entry point.

Production deployments must use a WSGI server, for example::

    gunicorn --bind 0.0.0.0:8000 wsgi:app
"""

from __future__ import annotations

import os

from app import create_app

app = create_app()


def _main() -> None:
    if app.config["ENVIRONMENT"] == "production":
        raise SystemExit(
            "run.py is for local development only. Use a WSGI server with wsgi:app in production."
        )

    host = os.getenv("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_RUN_PORT", "5000"))
    app.run(host=host, port=port, debug=app.config["DEBUG"])


if __name__ == "__main__":
    _main()
