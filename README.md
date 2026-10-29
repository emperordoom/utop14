# UTOP14

UTOP14 is a streetwear e-commerce platform built for Well Architected SOC 14.

**Current milestone:** Milestone 4 — authentication and role-based access
control. The storefront and catalog are database-backed (M3). Accounts support
customer, operator and admin roles, CSRF-protected registration/login/logout,
and server-side protected staff pages. Cart, checkout, orders and admin
inventory write tools are intentionally not implemented yet.

## Technology

- Python 3.12+ / Flask 3 application factory
- Jinja2, HTML5, CSS3, JavaScript
- PostgreSQL with Flask-SQLAlchemy and Psycopg 3
- Flask-Migrate (Alembic)
- Flask-Login
- Flask-WTF / CSRF protection
- pytest and Ruff
- Gunicorn and Nginx for production deployment

## Project layout

```text
utop14/
├── app/
│   ├── __init__.py          # create_app() application factory
│   ├── config.py            # environment configuration and validation
│   ├── extensions.py        # SQLAlchemy, Migrate, Login, CSRF instances
│   ├── main/                # main blueprint and public routes
│   ├── storefront/          # storefront blueprint and presentation helpers
│   ├── auth/                # registration, login, logout, account, RBAC
│   ├── admin/               # protected admin and operator dashboards
│   ├── catalog/             # deterministic launch catalog seed
│   ├── services/            # catalog and dashboard read models
│   ├── models/              # model registry imported by Alembic
│   ├── static/              # CSS, JavaScript, local SVG art and fonts
│   └── templates/
│       ├── base.html        # shared page layout
│       ├── components/      # navigation, footer and card partials
│       ├── auth/            # login, registration and account pages
│       ├── admin/           # staff dashboards
│       ├── errors/          # branded 403 and 404 pages
│       └── storefront/      # home, shop and product templates
├── migrations/              # Flask-Migrate/Alembic scaffold and revisions
├── tests/
│   ├── integration/         # endpoint, model, service and RBAC tests
│   └── unit/                # configuration, factory and helper tests
├── instance/                # local instance data (not committed)
├── run.py                   # development entry point
├── wsgi.py                  # WSGI entry point (wsgi:app)
├── pyproject.toml           # pytest and Ruff configuration
├── requirements.txt
└── .env.example
```

## Prerequisites

- Python 3.12 or newer (tested with Python 3.14.4)
- PostgreSQL with a local development database named `utop14_db`
- A virtual environment

## Local setup

1. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Create the local environment file:

   ```bash
   cp .env.example .env
   ```

4. Generate a development secret key and place it in `.env`:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

5. Create the PostgreSQL role and database. Replace `<local-password>` with a
   local development password; never commit it:

   ```sql
   CREATE USER utop14_dev WITH PASSWORD '<local-password>';
   CREATE DATABASE utop14_db OWNER utop14_dev;
   ```

6. Set `DATABASE_URL` in `.env`, URL-encoding any special characters in the
   password:

   ```dotenv
   DATABASE_URL=postgresql+psycopg://utop14_dev:<local-password>@localhost:5432/utop14_db
   ```

7. Apply migrations after database models and migration revisions exist:

   ```bash
   flask --app wsgi db upgrade
   ```

   The application never calls `db.create_all()` at startup. Schema changes
   must go through Flask-Migrate.

## Configuration

Configuration is loaded from environment variables. `python-dotenv` loads a
local `.env` file when present, but values already set in the process
environment take precedence. `.env` is ignored by Git.

| Variable | Required | Purpose |
| --- | --- | --- |
| `APP_ENV` | No | `development` (default), `production` or `testing` |
| `SECRET_KEY` | Yes | Flask session and CSRF signing key |
| `DATABASE_URL` | Yes | PostgreSQL URL using the `postgresql+psycopg://` driver |
| `FLASK_DEBUG` | No | Development debug toggle; defaults to `1` in development |
| `FLASK_RUN_HOST` | No | `run.py` bind address; defaults to `127.0.0.1` |
| `FLASK_RUN_PORT` | No | `run.py` port; defaults to `5000` |
| `TEST_DATABASE_URL` | No | Optional isolated PostgreSQL database for tests; must end in `_test` |
| `TEST_SECRET_KEY` | No | Optional test-only secret override |

Startup validation fails with a clear `ConfigurationError` when `SECRET_KEY`
or `DATABASE_URL` is missing or when a non-Psycopg database URL is supplied.
Error messages identify variable names only and never include secret values.

Production adds these mandatory safeguards:

- `DEBUG` and `TESTING` are forced off.
- `SECRET_KEY` must be at least 32 characters and cannot be a placeholder.
- `SESSION_COOKIE_SECURE` and `REMEMBER_COOKIE_SECURE` are enabled.
- Session and remember-me cookies remain `HttpOnly` with `SameSite=Lax`.
- CSRF protection remains enabled.

No default production secret is provided. Generate a unique secret for each
deployment and inject it through the deployment platform's secret store.

## Running locally

Start the development server:

```bash
python run.py
```

Alternatively use the Flask CLI and WSGI entry point:

```bash
flask --app wsgi run --debug
```

Open the storefront homepage at <http://127.0.0.1:5000/>.

Check the health endpoint:

```bash
curl http://127.0.0.1:5000/health
# {"status":"ok"}
```

The health endpoint is a liveness check only. It does not query the database
or expose configuration, credentials, versions or environment details.

## Storefront and catalog

`GET /` is served by the `storefront.home` endpoint from
`app/templates/storefront/home.html`. Products and categories are loaded from
PostgreSQL through `app.services.catalog`; `GET /shop` supports `category`,
`size`, `color` and `q` filters, and `GET /product/<slug>` renders variants,
stock state, gallery images and related pieces.

Editorial campaign copy and the shared `money` filter live in
`app/storefront/content.py`. Product prices are stored as PostgreSQL
`NUMERIC(12,2)` values and handled as `Decimal` in application code.

Design assets are stored locally:

- CSS: `tokens.css`, `base.css`, `components.css`, `home.css`, `catalog.css`,
  `auth.css`
- JavaScript: `nav.js` for progressive mobile-navigation enhancement
- Fonts: Archivo, Instrument Serif and Space Mono (self-hosted, OFL licensed)
- Original SVG artwork and favicon under `app/static/images/`

The page remains usable without JavaScript, with the menu visible. When
JavaScript is available, the disclosure toggle maintains `aria-expanded`, closes
on Escape, outside interaction or link activation, and resets at desktop width.
No external CDN, frontend framework or hotlinked image is used.

## Authentication and RBAC

Accounts use Flask-Login, Flask-WTF CSRF protection and Werkzeug password
hashing. The supported roles are:

| Role | Access |
| --- | --- |
| `customer` | Own account and public storefront |
| `operator` | Operator console plus customer access |
| `admin` | Admin dashboard plus all lower-level access |

Public authentication routes:

- `GET/POST /auth/register` — customer self-registration; the server always
  assigns the `customer` role.
- `GET/POST /auth/login` — session login with a safe local `next` redirect.
- `POST /auth/logout` — CSRF-protected logout.
- `GET /auth/account` — signed-in account details.

Protected staff routes:

- `GET /ops` — operator and admin only.
- `GET /admin` — admin only.

Authorization is enforced by the `role_required()` decorator in
`app/auth/permissions.py`; hiding navigation links is not relied upon for
security. Unauthenticated users are redirected to login, while authenticated
users without sufficient access receive a branded HTTP 403 page.

### Provisioning the initial admin

Privileged accounts are never created through public registration. Provision
the initial admin interactively:

```bash
flask --app wsgi users create-admin
```

The command prompts for email, full name and password with hidden password
input, refuses a duplicate email or a second admin, and never prints the
password. There is no public admin-registration endpoint.

## Tests

```bash
pytest
```

The suite runs against PostgreSQL `utop14_test`. Fixtures apply the committed
Alembic migrations, reject any database whose name does not end in `_test`, and
truncate account/catalog tables between tests. The development database is
never modified by the test suite.

Coverage includes application startup, configuration and production security
defaults, catalog models and constraints, catalog service queries, storefront
pages, seeds, registration, password hashing, login/logout, CSRF, open-redirect
prevention, inactive accounts, role-based access control and the admin CLI.

## Linting and formatting

```bash
ruff check .
ruff format --check .
```

To apply formatting:

```bash
ruff format .
```

## Database migrations

The Flask-Migrate scaffold is already initialized in `migrations/`. After
adding or changing models in `app/models/`, import each model module in
`app/models/__init__.py` so Alembic can discover its metadata, then run:

```bash
flask --app wsgi db migrate -m "describe the schema change"
flask --app wsgi db upgrade
```

Always review generated migration files before applying them. Do not run
destructive migration commands against production data without a backup and
explicit approval.

Current revision chain in source:

- `b93e6a5d9742` — catalog models
- `5b9c540efff4` — users and role constraint

The M4 users migration is generated and reviewed; apply it through the normal
controlled migration step after review.

## Production notes

1. Set `APP_ENV=production` and provide a strong `SECRET_KEY` and the
   production `DATABASE_URL` through the environment or secret manager.
2. Apply migrations from a controlled release job before starting new
   application instances.
3. Serve `wsgi:app` with Gunicorn behind Nginx over HTTPS, for example:

   ```bash
   gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app
   ```

   Install Gunicorn in the production image/runtime environment. It is not
   needed for local development or the current test suite.

4. Do not use `run.py` in production. It refuses to start when
   `ENVIRONMENT=production`.
5. Secure cookies require HTTPS; terminate TLS at Nginx and forward requests
   to Gunicorn on the loopback interface.
6. Keep `.env`, database credentials and secret keys out of source control,
   logs and error responses.

## Milestone 4 scope

Implemented:

- `User` model with normalized unique email, Werkzeug password hash, role,
  active flag, timestamps and nullable last-login timestamp
- Database role check constraint for `customer`, `operator` and `admin`
- Registration, login, logout and account pages with CSRF protection
- Server-assigned customer role; no client role escalation on registration
- Safe local `next` redirect handling and session clearing on authentication
- Inactive-account rejection and session invalidation
- Server-side `role_required()` decorator with customer/operator/admin hierarchy
- Admin-only `/admin` dashboard and operator-level `/ops` console
- Branded HTTP 403 page
- Interactive `flask --app wsgi users create-admin` bootstrap command
- Authentication, RBAC, CSRF, open-redirect and CLI tests

Not yet implemented: admin product/inventory CRUD, customer cart, checkout,
orders, rate limiting and password reset.

## Milestone 3 scope

Implemented:

- PostgreSQL catalog models: Category, Product, ProductVariant, ProductImage
- Database-backed homepage, shop listing, filtering and product detail pages
- Idempotent `flask --app wsgi catalog seed` launch catalog
- Catalog constraints, indexes, foreign-key behavior and image-path validation
- Initial catalog Alembic migration and PostgreSQL-backed catalog tests

## Milestone 2 scope

Implemented:

- Storefront blueprint with `GET /` served by `storefront.home`
- Responsive editorial homepage with hero, featured collection, product grid,
  category showcase, brand statement and footer
- Frozen mock content dataclasses with `Decimal` prices
- Original local SVG artwork and self-hosted fonts; no external CDNs or
  frontend frameworks
- Responsive CSS with accessible focus states and reduced-motion support
- Progressive-enhancement mobile navigation in `nav.js`
- Unit and integration tests for homepage content, routes and static assets

Not yet implemented: database-backed products and categories, product detail
pages, authentication, cart, checkout, order history and admin inventory
management.

## Milestone 1 scope

Implemented:

- Flask application factory with development, production and testing configs
- SQLAlchemy, Flask-Migrate, Flask-Login and CSRF initialization
- Environment loading and fail-safe validation
- Main blueprint with `/health`
- Development and WSGI entry points
- Migration-compatible model registry and initialized Alembic scaffold
- pytest and Ruff configuration with startup, config and health tests
- Setup, development, migration and production documentation

Not yet implemented: authentication, catalog, cart, checkout, orders, admin
management and storefront templates. Those belong to later milestones.
