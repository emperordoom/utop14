# UTOP14

UTOP14 is a streetwear e-commerce platform built for Well Architected SOC 14.

**Project status:**

- Integrated into `main`: M1–M11.
- Implemented and verified on `feature/admin-audit-log`, pending integration:
  M12 Admin User Management, M13 Admin Audit Log, and M13.2 Audit Log
  Hardening.
- Current: M13.5 CI validation and final integration readiness review.
- Pending and not started: M14 and later milestones.

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
│   ├── cart/                # persistent cart routes and forms
│   ├── checkout/            # checkout form and transactional placement
│   ├── orders/              # private order confirmation and history
│   ├── payments/            # payment routes, forms and simulated provider
│   ├── catalog/             # deterministic launch catalog seed
│   ├── services/            # catalog, cart, checkout, order and payment services
│   ├── models/              # model registry imported by Alembic
│   ├── static/              # CSS, JavaScript, local SVG art and fonts
│   └── templates/
│       ├── base.html        # shared page layout
│       ├── components/      # navigation, footer and card partials
│       ├── auth/            # login, registration and account pages
│       ├── admin/           # staff dashboards
│       ├── cart/            # cart page
│       ├── checkout/        # checkout page
│       ├── orders/          # order confirmation and history
│       ├── payments/        # payment initiation and attempt detail
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
| `TRUSTED_PROXY_HOPS` | No | Number of trusted reverse-proxy hops for `X-Forwarded-For`; default `0` |

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

## Shopping cart and checkout

Each signed-in account has exactly one persistent PostgreSQL cart. Cart routes
require authentication and every state-changing request is CSRF protected:

| Route | Method | Purpose |
| --- | --- | --- |
| `/cart` | GET | View the current user's cart |
| `/cart/add` | POST | Add or merge a variant |
| `/cart/update/<item_id>` | POST | Change a line quantity |
| `/cart/remove/<item_id>` | POST | Remove a line |
| `/checkout` | GET/POST | Review totals and place an order |
| `/orders/<order_number>` | GET | Owner-only order confirmation |

Cart rules:

- Only active products, active categories and active variants can be added.
- Quantities are positive integers, capped at 99 per line and current stock.
- Duplicate adds merge through the unique `(cart_id, variant_id)` constraint and
  PostgreSQL `ON CONFLICT` upserts.
- Prices and subtotals are always recalculated from current database prices.
- Cart ownership is enforced in every query; item IDs from other users return
  not-found behavior.

Checkout runs in one PostgreSQL transaction:

1. Lock the user's cart and cart lines.
2. Revalidate product, category, variant and stock state.
3. Recalculate line prices, subtotal, shipping and total with `Decimal`.
4. Create the order with status `pending` and payment status `unpaid`.
5. Create immutable order-item snapshots for product name, SKU, size, colour,
   unit price, quantity and line total.
6. Decrement stock with a conditional atomic `UPDATE ... WHERE stock >= quantity`
   and check the affected row count.
7. Clear the cart lines and commit only if every step succeeds.

Monetary invariants enforced by the checkout service and its tests:

- `OrderItem.line_total = OrderItem.unit_price × OrderItem.quantity`
- `Order.total = Order.subtotal + Order.shipping_cost`
- `Order.subtotal = sum of all OrderItem.line_total values`

These are application-level invariants. The M5 database schema enforces
non-negative monetary values with CHECK constraints, but it does not enforce the
arithmetic relationships above with database CHECK constraints or triggers.
Direct SQL writes outside the service must preserve these relationships
themselves.

Shipping is a flat `Rp 12`, waived at subtotal `Rp 200` or above. No payment
gateway or shipping provider is integrated. Stock is deducted when the order is
created. Cancellation and stock restoration are handled by the M6 order
lifecycle. Order confirmation is visible only to the account that owns the order.

## Order lifecycle and management

Customer routes:

| Route | Method | Purpose |
| --- | --- | --- |
| `/orders` | GET | Paginated order history for the signed-in customer |
| `/orders/<order_number>` | GET | Owner-only order detail |
| `/orders/<order_number>/cancel` | POST | Cancel a pending unpaid order |

Staff routes (operator and admin only):

| Route | Method | Purpose |
| --- | --- | --- |
| `/admin/orders` | GET | All orders with status/payment filters and order-number search |
| `/admin/orders/<order_number>` | GET | Customer, delivery, snapshots and lifecycle detail |
| `/admin/orders/<order_number>/status` | POST | Apply one permitted lifecycle transition |

Status transition matrix:

| Current | Allowed next | Notes |
| --- | --- | --- |
| `pending` | `processing`, `cancelled` | Customer cancellation requires unpaid payment |
| `processing` | `shipped`, `cancelled` | Cancellation allowed only while unpaid |
| `shipped` | `delivered` | No cancellation after dispatch |
| `delivered` | — | Terminal |
| `cancelled` | — | Terminal |

Payment status is never changed automatically by a status transition. Paid
orders cannot be cancelled until a refund workflow exists; this is intentional.

Cancellation runs in one transaction:

1. Lock the order row with `SELECT FOR UPDATE`.
2. Validate ownership and the current status/payment state.
3. Read order items deterministically.
4. Restore stock for each item whose original variant still exists.
5. Skip deleted variants safely; never match by SKU.
6. Set `cancelled_at`, `cancelled_by_user_id`, optional
   `cancellation_reason` and `status = cancelled`.
7. Commit only if all restoration succeeds; otherwise roll back everything.

Concurrent cancellations serialize on the order row lock, so stock is restored
once at most. The second request observes the cancelled state and is rejected.

## Payment integration

M7 introduces payment attempts for orders. The initial provider is a
development/testing-only simulation. No real money moves and no card data is
collected.

- Payment currency: **IDR** (`IDR`).
- Payment attempt deadline: **15 minutes**.
- Provider: **simulated**.
- Simulation is enabled in development/testing and disabled in production.
- The payment amount is always derived from `Order.total`; client-supplied
  amount, currency, provider and status are ignored.
- Monetary values use `Decimal` and PostgreSQL `NUMERIC(12,2)`.
- Product prices, shipping, orders and payments all use **IDR**.
- A single canonical `format_idr` formatter is used by the storefront, cart,
  checkout, order, admin and payment views.
- M7 does not apply an FX conversion and does not change stored prices or
  historical order values.
- M7 does not implement refunds or a real payment gateway.

Payment attempt statuses:

- `pending`
- `paid`
- `failed`
- `expired`
- `refunded` (reserved; no refund action in M7)

Allowed transitions:

| Current | Allowed next | Notes |
|---|---|---|
| `pending` | `paid` | Server-validated simulated success |
| `pending` | `failed` | Simulated failure |
| `pending` | `expired` | Deadline passed or order cancelled |
| `paid` | `refunded` | Reserved for a future confirmed refund workflow |
| `failed` | — | Terminal for that attempt |
| `expired` | — | Terminal for that attempt |
| `refunded` | — | Terminal |

Only one payment per order may be `paid`, enforced by a PostgreSQL partial unique
index. Multiple attempts are allowed while the order remains unpaid; a second
attempt cannot mark an already-paid order paid.

### Payment routes

| Route | Method | Purpose |
| --- | --- | --- |
| `/orders/<order_number>/pay` | GET | Owner-only payment page |
| `/orders/<order_number>/payments` | POST | Create a pending attempt; CSRF |
| `/payments/<payment_reference>` | GET | Owner-only payment attempt detail |
| `/payments/<payment_reference>/simulate` | POST | Development/testing simulation; CSRF |

Payment creation locks the order, validates ownership and eligibility, checks
idempotency, then creates a `pending` attempt with `amount = order.total`,
`currency = IDR`, and `expires_at = now + 15 minutes`. A duplicate POST with the
same idempotency key returns the existing attempt.

Payment processing locks the order first and the payment second, validates
ownership, provider, amount, currency, status and deadline, then updates the
payment and order in the same transaction. Failed and expired attempts leave
`Order.payment_status` unchanged as `unpaid`. A successful attempt sets it to
`paid`. Pending payments are expired when the order is cancelled.

### Simulation security

The simulated provider is offline and deterministic:

- No external payment service is contacted.
- No real money is processed.
- No card number, CVV or card expiry fields exist.
- Simulated provider references begin with `SIM-`.
- Simulation outcomes are restricted to `success` and `failure`.
- Expiry is determined by the server-side `expires_at`, not by a client action.
- Simulation requires login, ownership, CSRF and a pending payment attempt.
- Simulation routes return 404 when simulation is disabled.
- Production validation rejects `PAYMENT_SIMULATION_ENABLED=True` and the
  `simulated` provider.

In production, with no real provider configured, payment initiation returns HTTP
503. The order remains `unpaid`; M7 does not fake a production payment.

## Tests

```bash
pytest
```

The suite runs against PostgreSQL `utop14_test`. Fixtures apply the committed
Alembic migrations, reject any database whose name does not end in `_test`, and
truncate account, catalog, cart, order and payment tables between tests. The
development database is never modified by the test suite.

Coverage includes application startup, configuration and production security
defaults, catalog models and constraints, catalog service queries, storefront
pages, seeds, registration, password hashing, login/logout, CSRF, open-redirect
prevention, inactive accounts, role-based access control, the admin CLI, cart
constraints and concurrency behavior, checkout totals, price snapshots, stock
deduction, transaction rollback, order ownership, order history, cancellation,
stock restoration, lifecycle transitions, operator/admin order management,
payment constraints, IDR amounts, 15-minute deadlines, idempotency, simulated
success/failure/expiry, payment ownership, concurrent processing and production
payment gating.

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
- `f003cabb1f4f` — carts, cart items, orders and order items
- `b042768520c0` — order cancellation fields
- `c0f6c626195e` — payment attempts and one-paid-payment index
- `1b0a971b10c6` — private user avatar filename
- `2f863a992991` — manual-transfer payment proofs
- `7c1e4b9a2d30` — product reviews and ratings
- `3f7a2c9d1b64` — administrative audit log

## Admin audit logging and trusted proxy

M13 records four permanent administrative user-management events:

- `user.profile_updated`
- `user.role_changed`
- `user.activated`
- `user.deactivated`

Each record stores the actor and target identity snapshots, allowlisted
before/after JSONB snapshots, client IP, user agent, request ID and UTC
timestamp. User changes and their audit row are committed in one transaction;
an audit failure rolls the User mutation back. Audit records are append-only at
the application layer and protected against row-level UPDATE/DELETE by a
PostgreSQL trigger. The trigger permits only foreign-key `SET NULL` clearing of
the nullable actor/target identity links. Database owners, superusers,
`TRUNCATE` and a compromised privileged database account remain outside that
protection boundary.

Only admins can read `/admin/audit-logs`. There are no edit, delete, purge or
export routes. Retention is permanent until a separately approved archival
policy exists.

### Trusted proxy configuration

`TRUSTED_PROXY_HOPS` defaults to `0`. With the default, `ProxyFix` is not
enabled, `X-Forwarded-For` is ignored, and the application records the direct
peer address. Enable forwarded headers only when the application is actually
behind the stated number of trusted proxies.

`ProxyFix(x_for=N)` trusts the rightmost `N` forwarded addresses. The configured
hop count must match the real trusted proxy chain; an incorrect count can record
the proxy address or an attacker-controlled address as the client IP. No proxy
configuration should ever let untrusted clients control values the application
treats as trusted.

#### Single trusted Nginx proxy

For exactly one trusted Nginx proxy in front of Gunicorn, overwrite the forwarded
header with the immediate client address:

```bash
TRUSTED_PROXY_HOPS=1
```

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Request-ID $request_id;
```

`$remote_addr` is the address of the client connecting directly to Nginx and
overwrites any inbound `X-Forwarded-For` value. This is the least ambiguous
single-proxy configuration.

`$proxy_add_x_forwarded_for` is a different behavior: it appends the connecting
address to an existing forwarded chain. With one proxy and
`TRUSTED_PROXY_HOPS=1`, `ProxyFix` still uses only the rightmost address, so
client-supplied entries to the left are ignored; however, the request header
retains the untrusted chain. Do not treat the whole chain as trusted unless the
deployment has actually validated it.

#### Multiple trusted proxies

A multi-proxy deployment normally uses `$proxy_add_x_forwarded_for` at each
trusted proxy so each hop appends its immediate peer. Set
`TRUSTED_PROXY_HOPS` to the exact number of trusted proxies; for example, two
trusted proxies use `TRUSTED_PROXY_HOPS=2`. `ProxyFix` then selects the address
`N` positions from the right and ignores values further left. Every trusted hop
must append consistently, and the edge proxy must prevent untrusted clients from
injecting values into the portion of the chain the application trusts.

The same trust rules apply to inbound `X-Request-ID`: the application reuses a
valid inbound UUID only when trusted proxy hops are configured. A proxy should
overwrite it with a server-generated value (`$request_id`) rather than passing
an arbitrary client-supplied identifier.

### Audit technical debt

- **F-01 — actor/target filter performance:** current filters use partial
  `ILIKE '%term%'` on snapshot emails and joined current full names. The
  existing `(actor_id, created_at)` and `(target_user_id, created_at)` indexes do
  not accelerate those predicates. No `pg_trgm` extension or GIN migration is
  added without realistic volume/query-plan evidence; benchmark before changing
  the schema.
- **F-04 — unknown IP sentinel:** an unavailable or malformed remote address is
  stored as `0.0.0.0`; this is a sentinel, not a guaranteed real client address.
- **F-06 — database privilege boundary:** the trigger blocks ordinary row-level
  UPDATE/DELETE, but table owners, superusers, `TRUNCATE`, and a compromised
  privileged account remain outside its protection. Runtime DB roles are not
  separated by this application.
- **F-08 — JSONB validation:** PostgreSQL enforces JSON object type; flatness and
  sensitive-key exclusion are application-level controls. Direct privileged DB
  inserts are outside that allowlist.
- **F-09 — historical name search:** deleted users retain email snapshots, but
  current-name search no longer has a User row to join. Email search remains.
- **F-10 — no-op transaction contract:** no-op service paths roll back to release
  row locks; this assumes the service owns the top-level transaction.
- **F-11 — request ID trust:** inbound request IDs depend on correct proxy
  overwrite behavior and are not an authorization control.
- **F-12 — audit scope:** login, logout, password reset, order, payment, and
  failed-action auditing are outside M13 scope.

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

## Milestone 7 scope

Implemented:

- Dedicated `Payment` attempts with IDR amount snapshots
- Multiple attempts per order with one-paid-payment partial unique index
- Server-derived amount from `Order.total`; client price fields ignored
- 15-minute payment deadline and server-side expiry
- Idempotent payment initiation and repeated simulation
- Simulated provider with success/failure outcomes only
- Development/testing simulation gate; production returns HTTP 503
- Customer payment page, attempt detail and simulation controls
- Payment attempts on customer order confirmation and admin order detail
- Pending payments expired during order cancellation
- Payment, order status and lifecycle integration tests

Not yet implemented: real payment gateway, real refunds, card data handling,
webhook signature verification, provider reconciliation and notifications.

## Milestone 6 scope

Implemented:

- Customer order history with pagination and newest-first ordering
- Customer cancellation for pending unpaid orders with stock restoration
- Cancellation audit fields: timestamp, actor and optional reason
- Atomic cancellation transaction with order row locking and rollback
- Concurrent cancellation idempotency through row locks
- Operator/admin order queue with status/payment filters and order-number search
- Operator/admin order detail with customer, delivery and snapshot data
- Explicit lifecycle transition validation and CSRF-protected status updates
- Status badges, responsive order UI and branded empty states

Not yet implemented: payment refunds, shipping provider integration, audit table,
fulfillment notes and customer notifications.

## Milestone 5 scope

Implemented:

- Persistent one-cart-per-user `Cart` and unique `CartItem` lines
- `Order` and immutable `OrderItem` price snapshots with historical foreign keys
- Atomic cart upserts, stock validation and cross-user isolation
- Cart page, add-to-cart variant selection, quantity update and removal
- Transactional checkout with server-calculated Decimal totals
- Conditional atomic stock deduction and full rollback on failure
- Flat `Rp 12` shipping, free at `Rp 200` subtotal
- Owner-only order confirmation with status and payment state

Not yet implemented: payment gateway, shipping provider, cancellation, stock
restoration, order history, refunds and admin order management.

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
