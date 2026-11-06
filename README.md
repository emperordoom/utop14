# UTOP14

UTOP14 is a streetwear e-commerce platform built for Well Architected SOC 14.

**Project status:**

- See [`docs/PROJECT_ROADMAP.md`](docs/PROJECT_ROADMAP.md) for the durable
  phase-by-phase status, checkpoint evidence, and outstanding blockers.
- Development is in Phase 4 (independent approval and M14.3 integration).
  Phase 3 is complete based on the M14.3.23 approval of `a8e9a9b6…`.
  Production readiness is deferred and is not authorized by development
  completion.

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
| `SECURITY_EVENT_HASH_KEY` | Production | Dedicated HMAC-SHA256 key for authentication identifier hashes; at least 32 bytes, distinct from `SECRET_KEY`; optional in development/testing |
| `AUTH_RATE_LIMIT_*` | No | PostgreSQL fixed-window login rate-limit policy and TTL; defaults documented in `.env.example` and the authentication rate-limiting section. |
| `SECURITY_EVENT_RETENTION_*` | No | Per-type security-event retention, holds and bounded cleanup policy; defaults documented in `.env.example` and the retention section. |
| `CLOCK_SKEW_WARNING_SECONDS` | No | Advisory app/database clock-skew threshold in seconds (1–86400); default `120`, warning only. |

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

The suite is designed for a single pytest process. Do not run concurrent pytest
processes (including pytest-xdist) against the same `utop14_test` database:
fixtures truncate shared tables and the migration-cycle test mutates the schema.

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
- `9b2d4e6f8a10` — authentication security events
- `c4e7a1b9d2f6` — security event request ID index
- `e1b7c4a9d2f3` — authentication rate-limit buckets
- `b4d8e2f7a1c9` — login-throttled security event taxonomy
- `d7c1a9e4b2f8` — security-event retention holds, run log and function
- `e3b9f1c7a2d4` — retention hold lock trigger and function validation hardening
- `c4a9e2f7b1d8` — server-side admin security-event filter state
- `f5d2b8c3e1a6` — DB-time retention run-log integrity (B-03/B-05)

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
  privileged account remain outside its protection. M14.3.3/OPS-01 provides a
  separate DDL/schema-owner, app, retention-owner, and runner role model with
  ownership/verification scripts; the residual privileged-account boundary
  remains.
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
  failed-action auditing are outside M13 scope. M14.1 covers authentication
  events in the separate `security_events` table.

## Authentication security events

M14.1 records exactly three authentication events in a dedicated append-only
`security_events` table, separate from the M13 administrative `audit_logs`:

- `auth.login_succeeded` — form login or registration auto-login
- `auth.login_failed` — valid credential attempt with reason
  `unknown_account`, `inactive_account` or `invalid_password`
- `auth.logout` — user-requested logout

Each record stores event type, outcome, reason code, nullable actor and subject
identity, an optional HMAC-SHA256 identifier hash, client IP, sanitized user
agent, request ID, allowlisted JSONB metadata and a UTC timestamp. The table is
append-only for ordinary application operations and protected against row-level
UPDATE/DELETE by its own PostgreSQL trigger. The trigger permits foreign-key
`SET NULL` and a direct privileged UPDATE that clears the nullable actor/subject
identity links; email snapshots and every other field remain immutable under
those row-level rules. It is not absolute immutability against table owners,
superusers, `TRUNCATE`, or a compromised privileged account.

Event persistence is best-effort and uses a separate short-lived transaction.
An audit failure never changes whether login, registration or logout succeeds,
and it cannot poison the authentication transaction. The failure is logged
without credentials or raw identifiers.

`SECURITY_EVENT_HASH_KEY` is the dedicated HMAC-SHA256 key for unknown login
identifiers. `SECRET_KEY` is never used as a fallback. When configured, the key
must contain at least 32 bytes of UTF-8 key material, must not be a known
placeholder value, and must differ from `SECRET_KEY`. Production additionally
requires the key to be present. The key is never included in configuration error
messages or application logs. Generate it with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

In development and testing the key may be empty. In that case the event is still
recorded but the identifier hash is omitted and a once-per-process configuration
warning is logged; raw unknown identifiers are never stored. Authentication
continues normally. Changing the key makes older identifier hashes
non-comparable.

Unknown and inactive account paths perform a password verification against a
single precomputed dummy hash so they are not obviously cheaper than a real
password check. This narrows a timing difference; it is not a claim of perfectly
constant execution time. External login responses stay generic.

Event metadata uses an explicit per-event allowlist and never includes
passwords, password hashes, reset tokens, session cookies or IDs, CSRF tokens,
access tokens or raw request bodies. Authentication callers capture primitive
event fields and release the request session's checked-out connection before
best-effort event persistence, so a single auth request does not need two
simultaneous database connections merely to write an event.

The `security_events` table is indexed by request ID for incident correlation.
A reason-code index is deferred until the M14.2 viewer defines its filters and
the query pattern is measured.

### Authentication rate limiting (M14.3.1/M14.3.2)

M14.3.1 adds a PostgreSQL shared store for fixed-window authentication rate
limiting. M14.3.2 wires the limiter into form login. Registration, password
reset and other endpoints are not rate-limited by this milestone. No Redis or
new rate-limiting dependency is used.

Bucket keys are HMAC-SHA256 values derived from `SECURITY_EVENT_HASH_KEY` with
the `utop14.auth_rate_limit.v1` domain and a scope-specific input. Raw email
addresses, IP addresses, usernames, passwords and session values are never
stored in `auth_rate_limits`.

The default policy is:

| Scope | Thresholds | Cooldowns | Maximum cooldown |
| --- | --- | --- | --- |
| Identifier | 5, 10, 20 failures | 60s, 300s, 900s | 900s |
| IP | 30, 60 failures | 300s, 900s | 1,800s |
| Combined IP + identifier | 10 failures | 300s | 900s |

All scopes share a 900-second fixed window. A bucket row stores
`window_start`, `failure_count`, optional `blocked_until` and `updated_at`.
The counter and window rollover use PostgreSQL
`INSERT ... ON CONFLICT ... DO UPDATE` in a short transaction. An active
cooldown is not extended by further failed requests; after the window expires,
the counter starts at one.

The login flow validates CSRF/form input, derives all three bucket keys, checks
cooldowns before user lookup, and returns a generic HTTP `429` with
`Retry-After` when blocked. Password verification is not run for a throttled
request. The response is non-cacheable and does not reveal whether the account
exists. A successful login resets the identifier bucket but not the IP bucket.
A rate-limit store failure is fail-open: authentication continues and a safe
warning with request ID, scope and exception type is logged. No local fallback
store or retry loop is used.

A new `auth.login_throttled` security event records meaningful block
transitions with reason codes `ip_rate_limited`, `identifier_rate_limited` or
`combined_rate_limited`. Its metadata allowlist is `scope`,
`retry_after_seconds`, `window_seconds` and `failure_count`. The event is
written once per new block transition; requests that are already blocked do not
create repeated events.

Relevant environment variables are documented in `.env.example`. The
`*_MAX_FAILURES` values must match the final entry in the corresponding
threshold list. The TTL defaults to 48 hours and must exceed the window plus the
scope's maximum cooldown.

Stale buckets are deleted in bounded batches by the foundation service. The
operational command is:

```bash
flask --app wsgi auth-rate-limit cleanup --batch-size 1000
```

The command deletes only rows whose `updated_at` is older than the cutoff
(`updated_at < now - AUTH_RATE_LIMIT_BUCKET_TTL_HOURS`). A row exactly at the
cutoff is retained. There is no scheduler or background worker; deployment must
invoke the command through an approved cron/systemd/maintenance job. Cleanup
never touches `security_events`, `audit_logs`, retention holds or retention run
logs.

Migration `e1b7c4a9d2f3` is additive. Its downgrade removes the
`auth_rate_limits` table and all current rate-limit state; it does not modify
security-event or audit-log history. Migration `b4d8e2f7a1c9` extends the
security-event taxonomy for `auth.login_throttled`; downgrade removes those
allowed values and requires existing throttled events to be archived first.

### Security-event retention (M14.3.3)

Retention applies only to the authentication `security_events` table. Admin
`audit_logs` M13 remain permanent and are never purged by this job. The default
policy is:

| Event type | Retention |
| --- | --- |
| `auth.login_succeeded` | 90 days |
| `auth.logout` | 90 days |
| `auth.login_failed` | 180 days |
| `auth.login_throttled` | 180 days |

Retention uses the PostgreSQL clock for every decision. New security events get
`created_at` from the column's `now()` default; the retention run reads
`SELECT now()` once and reuses that single cutoff for every scope and batch.
The retention function keeps PostgreSQL-time guards and excludes active holds
with `expires_at > now()`. Event types outside this policy are never deleted.

Investigative holds live in `security_event_retention_holds`. At most one hold
row exists per event; an active hold (`expires_at > now()`) prevents deletion.
Expired holds may be replaced. Hold creation accepts a relative duration, and
PostgreSQL generates `created_at`/`expires_at` from database time; callers do
not supply an arbitrary absolute expiry. Every hold write takes a per-event
advisory lock through the `security_event_retention_holds_lock` database
trigger, which uses the same `(7381, security_event_id)` lock as the cleanup
function. This applies to service calls and direct SQL, so a successful hold and
a concurrent cleanup cannot delete the event. An UPDATE that moves a hold to
another event locks both event ids in deterministic order. A direct UPDATE
cannot expire or shorten an active hold, and hold duration is capped at 3650
days. The app role keeps UPDATE only to replace an already-expired hold. Holds
and run-log rows are separate from `security_events` and are not deleted by
retention.

Retention configuration is bounded: `SECURITY_EVENT_SUCCESS_RETENTION_DAYS`
must be 90–3650, `SECURITY_EVENT_FAILURE_RETENTION_DAYS` 180–3650, and
`SECURITY_EVENT_RETENTION_MAX_DAYS` 1–3650 and at least the largest retention
period. The database function independently rejects a NULL/unknown scope and a
batch index outside 0–99.

Retention runs are recorded in `security_event_retention_runs` with non-PII
operational fields: run id, batch index, scope, cutoff, deleted count, status,
executed-by principal, error code, and database-generated start/finish
timestamps. Run logs are retained for one year by default; their cleanup is a
separate operational decision.

Each batch uses an explicit two-phase protocol. `begin_retention_run` commits a
`started` row with `executed_by = session_user`, `deleted_count = 0` and
`started_at = clock_timestamp()`. `prune_security_events` locks that run row
with `SELECT ... FOR UPDATE`, verifies the caller principal, `started` state,
scope and exact cutoff, deletes eligible events, and marks the same row
`success` with the actual count in the same transaction. `abandon_retention_run`
can change only a `started` row owned by the same `session_user` to `failed`
with an allowlisted error code. The only permitted transitions are
`started → success` and `started → failed`. There is no generic
`log_run(status, deleted_count)` entry point, and the runner cannot INSERT run
rows directly or use the run sequence.

`executed_by` identifies the database principal (normally
`utop14_retention_runner`), not a human or an OS job name. A process that dies
after `begin` leaves a `started` row; `flask --app wsgi
security-event-retention orphans --older-than-minutes N` lists these orphaned
rows for monitoring. The old synthetic `partial` row is no longer written; an
exhausted batch budget is reported with exit code `2` and a metric, while
historical `partial` rows remain untouched.

The cleanup entry point is a `SECURITY DEFINER` function,
`public.prune_security_events`, owned by `utop14_retention_owner`. It locks
`search_path` to `pg_catalog, public`, schema-qualifies application objects,
validates scope/cutoff/batch limits, excludes active holds, and deletes only
rows older than the policy cutoff. The append-only trigger permits DELETE only
when `current_user` is that owner. Application and runner roles cannot
DELETE/UPDATE/TRUNCATE `security_events`. Role creation is deliberately outside
migrations; see `scripts/security_event_retention_roles.sql` and verify with
`scripts/security_event_retention_verify.sql`. The verify script uses
`ON_ERROR_STOP` and raises on the first failed required assertion, so it exits
non-zero; run it as a PostgreSQL superuser, not as `utop14_app`. A non-superuser
schema owner cannot run the `SET ROLE` probes and fails the explicit
verification preflight.

M14.3.12 hardens the provisioning and verification gates:

- Role memberships are **default-deny** for `utop14_app`,
  `utop14_retention_owner`, and `utop14_retention_runner`. Verification fails on
  any direct or transitive membership, regardless of `INHERIT`, `SET`, `ADMIN`,
  predefined role, custom role, or nested path. The explicit allowlist is
  empty; a membership may only be added after a documented review in both the
  provisioning and verification scripts.
- Provisioning removes every forward membership of a managed role and fails
  closed on a reverse membership (another role can assume a managed role).
- Verification inventories every non-system schema, user-defined
  type/domain/enum/composite, extension, table, sequence, function, trigger,
  and view. Only `public` and `plpgsql` are approved today; any other object
  fails verification until the inventory is reviewed and updated.
- The app has no `CREATE` or `USAGE` outside `public`, and no `CREATE` through
  `PUBLIC` or a custom role.
- The app has **no function `EXECUTE` at all**, including the
  `security_event_retention_holds_lock` trigger helper. PostgreSQL checks
  trigger-function `EXECUTE` when the trigger is created, not when it fires, so
  app hold INSERT/UPDATE still works. `begin_retention_run`,
  `abandon_retention_run`, and `prune_security_events` remain executable only by
  `utop14_retention_runner` (and their owner).
- Provisioning is transactional, preflighted, and repeatable: guarded role
  creation, explicit attribute reconciliation, migration-head check, object and
  ownership inventory, dangerous-default-ACL check, and membership
  reconciliation. A second run succeeds with identical non-owner ACLs and
  ownership; a preflight failure rolls back and can be corrected and rerun.

M14.3.14 closes the remaining direct-ACL verification gaps:

- Verification inspects table ACLs, column ACLs (`pg_attribute.attacl`),
  effective column privileges (`has_column_privilege`), sequence ACLs, function
  ACLs, and `GRANT OPTION`. No explicit column-level grant is approved for
  `utop14_app`, either retention role, or PUBLIC. Table-level grants legitimately
  apply to every column and must match the approved table matrix; a
  column-only grant on a table or column outside that matrix fails.
- Database-level `CREATE` is revoked from the app, retention roles, and PUBLIC,
  and verification fails if it reappears. Required CONNECT/TEMP privileges are
  preserved.
- PostgreSQL 17+ `MAINTAIN` is rejected for managed roles and PUBLIC. On
  PostgreSQL 16 the MAINTAIN-specific check is skipped with an INFO notice.
- Verification requires a PostgreSQL **superuser** because the runtime probes
  use `SET ROLE`. A non-superuser schema owner or ordinary role fails the
  explicit preflight; an inability to execute a probe is never reported as
  PASS. The script sets `search_path = pg_catalog, public` and schema-qualifies
  privilege checks so caller search paths cannot shadow application objects.
- Provisioning sets `ALTER ROLE utop14_app SET search_path = public,
  pg_catalog`, revokes database-level `CREATE`, and relies on the full table
  grant reset to remove column ACLs and `MAINTAIN`. Postconditions cover
  database CREATE, the app search_path, and the absence of non-owner column
  ACLs.
- Existing application connections and connection pools keep their old session
  `search_path` until they reconnect; recycle pools after provisioning.

M14.3.16 closes the parameter-ACL and persistent-GUC gaps:

- Verification inspects `pg_parameter_acl` and `has_parameter_privilege` for
  every parameter `SET` and `ALTER SYSTEM` grant. Managed roles and PUBLIC must
  have no such grant and no GRANT OPTION. Effective privileges through PUBLIC or
  a custom-role membership path are rejected; unrelated DBA/custom-role grants
  are not treated as application privileges.
- The project supports PostgreSQL 16+; if `pg_parameter_acl` or
  `has_parameter_privilege` is unavailable, verification and provisioning fail
  closed instead of silently skipping the check.
- Persistent GUCs are checked catalog-wide, not by a short dangerous-name list:
  - `utop14_app` role-level settings must be exactly
    `search_path=public, pg_catalog` (one entry, no extras).
  - Retention owner/runner must have no role-level or database-specific settings.
  - `utop14_schema_owner` may have `search_path` only; any other persistent GUC
    requires explicit DBA reconciliation.
  - Database-specific settings for managed roles are rejected; provisioning
    resets them with `ALTER ROLE ... IN DATABASE ... RESET ALL`.
  - Database-wide/global settings that affect application sessions are rejected
    with a DBA-reconciliation error; verification and provisioning never
    silently modify unrelated roles.
- Provisioning resets all persistent role-level and database-specific GUCs for
  the managed roles, applies the approved app search_path, and revokes parameter
  `SET`/`ALTER SYSTEM` grants for managed roles and PUBLIC (including dependent
  grants via `CASCADE`). Postconditions cover parameter ACLs, role-level GUCs,
  database-specific GUCs, database-wide GUCs, and the app search_path.
- The disposable test includes direct, PUBLIC, GRANT OPTION, ALTER SYSTEM,
  custom-role, role-level, database-specific, database-wide, hostile-schema, and
  second-run provisioning cases.
- PostgreSQL 16 parameter/GUC runtime behavior was not available for testing in
  this environment; the catalog/function/syntax compatibility is inspected, but
  only PostgreSQL 18.6 was runtime-tested.

M14.3.18 closes the cross-database and cluster-level gaps:

- Persistent GUC inspection is cluster-wide, not current-database-only:
  - Every `pg_db_role_setting` row for `utop14_app`,
    `utop14_retention_owner`, and `utop14_retention_runner` is inspected,
    regardless of `setdatabase`; no managed-role database-specific setting is
    approved in any database.
  - Every `pg_db_role_setting` row for `utop14_schema_owner` is inspected;
    `search_path` is allowed, anything else requires DBA reconciliation.
  - Every `setrole = 0` row (database-wide and global) is inspected; any
    database-wide setting fails closed because it can affect application
    sessions in that database.
  - Provisioning resets managed-role role-level settings and every
    managed-role/database-specific setting in every non-template database; it
    re-applies the approved app search_path and fails closed if a database
    cannot be reconciled.
- Schema-owner parameter ACLs are now default-deny: direct/effective
  `SET`/`ALTER SYSTEM`, PUBLIC, GRANT OPTION, and membership paths are checked;
  explicit schema-owner parameter grants are revoked by provisioning. A
  superuser schema owner’s implicit privileges are treated as the trusted DBA
  boundary, not an explicit ACL.
- Sensitive cluster-level GUCs are checked through `pg_settings` and
  `pg_file_settings`. Any sensitive setting in `postgresql.auto.conf`
  (`shared_preload_libraries`, `session_preload_libraries`,
  `local_preload_libraries`, `log_statement`, logging controls, `search_path`)
  fails verification and provisioning, including pending-restart entries.
  DBA-managed sources (`postgresql.conf`, command line, environment) are
  reported as INFO for operational review; they are not app-writable.
- The parameter/GUC catalog references introduced in M14.3.18 are
  `pg_catalog`-qualified. M14.3.19 later showed that the rest of the verifier
  still relied on the search path; see M14.3.20 below.
- Provisioning failure injection covers a failure after cross-database resets:
  the transaction rolls back the cross-database settings, and a rerun
  reconciles them. PostgreSQL does not emit event-trigger DDL commands for
  `ALTER ROLE`, so GUC-reset failure injection uses the post-reset GRANT failure
  path and parameter REVOKE failure separately.
- PostgreSQL 16 was not available for runtime testing; catalog/function/syntax
  compatibility is statically inspected only. Only PostgreSQL 18.6 was
  runtime-tested.

M14.3.20 completes catalog qualification for the verifier, provisioner, and
ownership template:

- **M14.3.19 finding — temporary-catalog shadowing produced a false PASS.**
  The scripts resolved several `pg_catalog` relations through the search path
  (for example `FROM pg_class c`) and used unqualified `regclass` literals such
  as `'pg_class'::regclass`. For relation and type names PostgreSQL searches
  `pg_temp` **before** `pg_catalog`, so a session-local
  `CREATE TEMP TABLE pg_class AS SELECT * FROM pg_catalog.pg_class` shadows the
  catalog regardless of the `search_path` setting. A verifier session pre-loaded
  that way returned exit 0 (false PASS) while `utop14_app` held `GRANT OPTION`
  on `public.audit_logs`, and the app could then run
  `GRANT SELECT ON public.audit_logs TO PUBLIC`.
- `SET search_path = pg_catalog, public` does **not** prevent this, because the
  temporary schema precedes `pg_catalog` for relation and type name lookup.
  Function and operator lookup behave differently: `pg_temp` is only searched
  for those when it is listed explicitly, so a temporary function cannot shadow
  an unqualified ACL helper under the enforced path. Qualification is still
  required, because the path is an explicit setting rather than a guarantee.
- **Remediation.** Every system catalog relation, ACL/privilege helper, and
  `regclass` literal in `scripts/security_event_retention_verify.sql`,
  `scripts/security_event_retention_roles.sql`, and
  `scripts/security_event_retention_ownership_template.sql` now carries an
  explicit `pg_catalog.` qualifier, for example `FROM pg_catalog.pg_class c`,
  `pg_catalog.has_table_privilege(...)`, and
  `'pg_catalog.pg_class'::regclass`. Catalog object identity can no longer change
  because a temporary or ordinary-schema object of the same name exists. SQL
  keywords that look like functions (`COALESCE`, `CURRENT_USER`, `SESSION_USER`,
  `CASE`, ...) are parsed as keywords, are not name-resolved, and cannot be
  qualified.
- **Regression coverage.** The disposable privilege test loads temporary copies
  of `pg_class`, `pg_attribute`, `pg_proc`, `pg_namespace`, `pg_depend`,
  `pg_type`, `pg_trigger`, and `pg_extension` into the verifier's own session
  while `utop14_app` holds `GRANT OPTION`, and requires every run to exit
  non-zero without the success marker. It also runs provisioning and the
  ownership template with a shadowed `pg_class` and requires correct behavior
  against the real catalog or a fail-closed abort, plus hostile ordinary-schema
  and temporary-function variants.
- **Schema-owner `search_path` rationale.** `utop14_schema_owner` may keep
  `search_path` at role level and per database because it is the trusted DDL
  boundary: it already owns the application schema and objects, so a
  `search_path` value adds no capability. It remains default-deny for parameter
  ACLs (`SET`/`ALTER SYSTEM`, PUBLIC, GRANT OPTION), so it cannot use
  `search_path` to change session or cluster configuration, and provisioning
  does not reset the schema-owner `search_path`.
- **Cluster-wide provisioning scope.** Provisioning resets managed-role
  role-level settings and every managed-role/database-specific setting in
  **every non-template database in the cluster**, including databases that
  belong to unrelated applications. The resets are catalog updates on
  `pg_catalog.pg_db_role_setting` (no connection to the target database is
  opened), so the blast radius is cluster-wide catalog state, not application
  data. Run provisioning only against the cluster that hosts UTOP14, during a
  change window, and expect `utop14_*` role settings to be removed from other
  databases on that cluster.
- Catalog qualification and its regression tests are local implementation
  results. They are not independent security approval; a separate review is
  still required before merge or production use.

#### Cluster-level GUC audit procedure

Run as a PostgreSQL superuser before relying on verification:

```sql
SELECT name, setting, source, sourcefile, pending_restart
FROM pg_settings
WHERE name IN (
    'shared_preload_libraries', 'session_preload_libraries',
    'local_preload_libraries', 'log_statement',
    'log_min_duration_statement', 'log_min_error_statement',
    'log_min_messages', 'log_destination', 'logging_collector',
    'log_connections', 'log_disconnections', 'log_duration',
    'log_hostname', 'log_line_prefix', 'log_statement_sample_rate',
    'log_transaction_sample_rate', 'search_path'
)
ORDER BY name;

SELECT sourcefile, name, setting, applied, error
FROM pg_file_settings
WHERE name IN (
    'shared_preload_libraries', 'session_preload_libraries',
    'local_preload_libraries', 'log_statement',
    'log_min_duration_statement', 'log_min_error_statement',
    'log_min_messages', 'log_destination', 'logging_collector',
    'log_connections', 'log_disconnections', 'log_duration',
    'log_hostname', 'log_line_prefix', 'log_statement_sample_rate',
    'log_transaction_sample_rate', 'search_path'
)
ORDER BY sourcefile, name;
```

- A sensitive setting whose `sourcefile` ends in `postgresql.auto.conf` must be
  reset with `ALTER SYSTEM RESET <name>;`. Reload with
  `SELECT pg_reload_conf();` for reloadable settings; if `pending_restart` is
  true or the setting has postmaster context, restart the cluster through the
  approved operational process.
- After reload/restart, re-run both queries and require the setting to be at its
  approved/default value with `pending_restart = false`; then re-run
  `security_event_retention_verify.sql`.
- Settings sourced from `postgresql.conf`, the command line, environment, or
  service configuration are DBA-managed. The verifier reports them as INFO;
  review them against the approved operational baseline. Do not edit production
  configuration files from this project.
- The verifier does not claim to inspect settings it cannot see through
  `pg_settings`/`pg_file_settings`; the audit above is the operational gate.


### Production ownership model (OPS-01)

The append-only and retention boundary depends on ownership separation. The
following model is mandatory in production and must be verified on a disposable
PostgreSQL cluster with a separate DDL role:

- A dedicated DDL/schema owner (or DBA) runs every migration and owns the
  database, application schema, every application table and sequence
  (including `audit_logs`, `auth_rate_limits`, `security_events`, all catalog,
  cart, order, payment and review tables), and the trigger/helper functions.
- The application login role is DML-only. It is **not** the database owner,
  schema owner, table owner, sequence owner, or function owner, and it has no
  `CREATE` on the application schema or the application database. It has no
  role memberships, no function `EXECUTE` (including trigger/helper functions),
  no explicit column-level grants, no `GRANT OPTION`, no parameter `SET` or
  `ALTER SYSTEM`, and no persistent GUC other than
  `search_path=public, pg_catalog` in any database.
- `utop14_retention_owner` remains NOLOGIN and owns
  `public.begin_retention_run`, `public.abandon_retention_run`, and
  `public.prune_security_events`. It has `SELECT, INSERT, UPDATE` on the run log
  and `USAGE, SELECT` on the run sequence. `utop14_retention_runner` remains
  separate, has only run-log `SELECT` for telemetry, and has neither INSERT on
  the run log nor any sequence privilege; it can only `EXECUTE` the three
  protocol functions. Neither retention role has database `CREATE`, explicit
  column grants, `GRANT OPTION`, parameter `SET`/`ALTER SYSTEM`, or persistent
  GUC settings in any database.
- `utop14_schema_owner` may have `search_path` only; any other role-level or
  database-specific GUC requires explicit DBA reconciliation. Explicit
  schema-owner parameter `SET`/`ALTER SYSTEM` grants are default-deny.
- The app grant matrix is least-privilege and complete:
  - `SELECT, INSERT` on `security_events`, `audit_logs`, and `order_items`
    (append-only/immutable writes; no UPDATE/DELETE).
  - `SELECT, INSERT, UPDATE` on `users`, catalog tables, carts, orders,
    payments, payment proofs, product reviews, and retention holds.
  - `SELECT, INSERT, UPDATE, DELETE` on `auth_rate_limits` (successful-login
    reset and TTL cleanup), `cart_items`, and `product_images`.
  - No app privileges on `security_event_retention_runs` (owner/runner only) or
    `alembic_version` (migration metadata).
  - `USAGE, SELECT` on every application sequence the app inserts into, and no
    `UPDATE` on any sequence; the retention run sequence is owner-only.
  - No `TRUNCATE`, `TRIGGER`, `REFERENCES`, or `MAINTAIN` on any application
    table; no ownership; no function `EXECUTE`; no column-level grants; no
    `GRANT OPTION`.
- `PUBLIC` has no function `EXECUTE`, no `CREATE` on any non-system schema, no
  database `CREATE`, no table/sequence privileges, no column privileges, and no
  `GRANT OPTION`.

`scripts/security_event_retention_ownership_template.sql` is a review-and-adapt
DBA template that transfers all 18 application tables, all 16 sequences, and
the trigger/helper functions to the schema owner; it is not run by migrations.
It preflights the exact object inventory (including schemas, types, extensions,
functions and triggers), runs in one transaction, and fails closed if a new
migration object has not been added to the inventory. After the DBA applies it
and runs the provisioning script, `scripts/security_event_retention_verify.sql`
must exit 0 when run as a PostgreSQL superuser. The verification script
inventories every schema, type, extension, table, sequence, function, trigger
and view, enforces default-deny memberships, checks ownership and the complete
app/owner/runner table, column, sequence and function ACL/EXECUTE matrices
(including `GRANT OPTION`), checks database-level `CREATE` and PostgreSQL 17+
`MAINTAIN`, checks `pg_parameter_acl` for `SET`/`ALTER SYSTEM` grants and
GRANT OPTION for app/retention/schema-owner/PUBLIC, checks all role-level and
database-specific GUCs in **every database** against the approved allowlist,
checks database-wide/global settings in every database for DBA reconciliation,
checks sensitive cluster-level settings in `pg_settings`/`pg_file_settings`
(any `postgresql.auto.conf` entry fails), checks every non-system schema for
app/retention `CREATE` and `USAGE`, and probes append-only boundaries. The
ownership model is only considered verified when the disposable
ownership/privilege test passes the rate-limit, audit, security-event,
trigger-disable, ALTER, DELETE, TRUNCATE, membership, schema, type, column-ACL,
database-CREATE, MAINTAIN, parameter-ACL, role-GUC, database-GUC,
cluster-GUC, function-EXECUTE, provisioning-idempotency, cross-database and
negative-grant probes.

Provisioning requires PostgreSQL 16 or newer. Parameter ACLs use
`pg_parameter_acl` and `has_parameter_privilege` (PostgreSQL 15+); if those are
unavailable, provisioning and verification fail closed. The membership option
columns `INHERIT`/`SET`/`ADMIN` are read through `to_jsonb` and a missing option
is treated as `TRUE` on older catalogs, so they do not falsely pass an
unverifiable membership. The scripts assume the role names
`utop14_schema_owner`, `utop14_app`, `utop14_retention_owner`, and
`utop14_retention_runner`; replace them consistently if the deployment uses
different names.

Provisioning and recovery:

1. Run migrations as the schema/DDL owner, then the ownership template, then
   `scripts/security_event_retention_roles.sql`, then the verify script as a
   PostgreSQL superuser.
2. The roles script is repeatable: a second run succeeds and produces the same
   non-owner ACL and ownership state. It creates missing retention roles,
   reconciles their `LOGIN`/`INHERIT`/privilege attributes, resets all
   persistent role-level and database-specific GUCs for the managed roles in
   every non-template database, sets the app `search_path` to
   `public, pg_catalog`, revokes database-level `CREATE`, and revokes parameter
   `SET`/`ALTER SYSTEM` grants for app/retention/schema-owner/PUBLIC. It never
   reads or changes passwords.
3. A forward membership of `utop14_app`, `utop14_retention_owner`, or
   `utop14_retention_runner` is removed by provisioning and reported with
   `REVOKED forbidden membership`. A reverse membership (another role can
   assume a managed role) fails preflight; review it, run
   `REVOKE <managed_role> FROM <other_role>`, then rerun.
4. A role with `SUPERUSER`/`CREATEDB`/`CREATEROLE`/`REPLICATION`/`BYPASSRLS`
   fails preflight; correct it with `ALTER ROLE ... NOSUPERUSER NOCREATEDB
   NOCREATEROLE NOREPLICATION NOBYPASSRLS` and rerun. Preflight failure is
   transactional: no partial grants remain.
5. Database-wide GUCs, non-`search_path` schema-owner GUCs, and sensitive
   `postgresql.auto.conf` settings are not modified automatically. Verification
   and provisioning fail with a DBA-reconciliation message; follow the
   cluster-level GUC audit procedure above, reset the setting, reload/restart
   if required, then rerun.
6. A pre-existing column-level grant, database `CREATE`, `MAINTAIN`, or
   parameter privilege is removed by the roles script, including managed-role
   settings in other databases. Verification fails if a forbidden grant or GUC
   is reintroduced after provisioning. Recycle existing application connections
   and pools after provisioning so they pick up the new `search_path`.
7. Any new schema, extension, type/domain, table, sequence, function, trigger
   or view must be reviewed and added to the ownership/provisioning inventory
   before provisioning or verification will pass. Only `public` and `plpgsql`
   are approved today.


M14.5.1.1 deployment requires a maintenance window because the run-log schema,
protocol functions and runner privileges change together:

1. Back up the database and verify a restore point.
2. Stop the retention timer and any manual retention invocation.
3. Apply migration `f5d2b8c3e1a6` as the DBA/superuser if the functions are
   already owned by `utop14_retention_owner`.
4. Run `scripts/security_event_retention_roles.sql` (it also updates the
   expected Alembic head to `f5d2b8c3e1a6`).
5. Run `scripts/security_event_retention_verify.sql` as a superuser; deploy only
   on exit 0.
6. Deploy the application/CLI code and run a small smoke retention run; confirm
   a `success` row with the runner principal and confirm the runner cannot
   INSERT a run row or use the sequence.
7. Restart the retention timer.

Migration `f5d2b8c3e1a6` has a **limited schema-only downgrade**, not a pure
forward-only path. The downgrade:

- runs only when `security_event_retention_runs` is empty; any run-log history
  makes it fail closed;
- restores the previous `prune_security_events` function, including its legacy
  ability to write a success row without the two-phase begin/abandon protocol;
- drops the `executed_by` column and the new protocol functions;
- must never be used as a production rollback procedure;
- must never be forced by deleting or merging historical retention run-log rows.

Production rollback is **restore-from-backup** using a verified backup taken
before deployment. A snapshot of the pre-deployment run log is the operational
recovery artifact. The limited downgrade exists only for disposable/empty
schema-cycle testing and controlled local recovery.

The hardening migration `e3b9f1c7a2d4` and the run-log integrity migration
`f5d2b8c3e1a6` replace retention functions. On a fresh install they run before
provisioning, while the functions are still owned by the DDL role. If
provisioning has already transferred them to `utop14_retention_owner`, run the
migration as the DBA/superuser (or temporarily transfer function ownership, run
it, and re-run provisioning). A non-superuser DDL role cannot replace a function
it does not own.

#### Residual risks (RR-03/RR-04)

These are explicitly accepted for this milestone; the hold and run-log designs
are intentionally not expanded here.

- **RR-03 — hold mutability.** The app role has `UPDATE` on holds because it
  must replace an already-expired hold. It can therefore extend an active hold
  up to 3650 days (repeatedly) and can change `reason`/`created_by` through a
  direct UPDATE. This can delay retention and means forensic hold metadata is
  not fully immutable. It is **not** a deletion bypass: the database trigger
  rejects expiring or shortening an active hold, and the retention function
  excludes active holds. If hold metadata must be tamper-evident, a future
  milestone should make holds append-only or expose a SECURITY DEFINER hold API
  with an immutable history.
- **RR-04 — run-log writer (remediated).** `utop14_retention_runner` no longer
  has direct INSERT on the run log or USAGE on its sequence, and success is only
  written by `prune_security_events` after a real delete in the same
  transaction. The remaining trusted boundary is the runner credential itself:
  it can begin a `started` row (an orphan if the process dies) and call the
  protocol functions. Protect its credential in a secret manager and restrict
  the OS job account. Treat the run log as operational telemetry, not a
  tamper-evident security audit trail.

The application sequence privileges (including `security_events_id_seq`,
`audit_logs_id_seq`, and all catalog/cart/order/payment/review sequences) are
applied by `scripts/security_event_retention_roles.sql`, not by an Alembic
migration. Grants are role provisioning, not schema DDL; keeping them outside
migrations avoids coupling schema versioning to role existence and preserves
the existing single Alembic head `f5d2b8c3e1a6`. All sequences remain owned by
the schema/DDL owner.

Deferred operational risks (documented, not silently fixed here):
- Identifier-bucket throttling can be used for targeted login denial of
  service; thresholds/cooldowns are configurable and should be monitored.
- Rate-limit windows/cooldowns, payment/order expiry and admin filter-state TTL
  use application time; production requires accurate synchronized clocks (NTP)
  on every application node. Security-event creation, retention cutoffs, holds
  and run timestamps use the PostgreSQL clock.
- M14.2 F-02 (viewer query-string/access-log exposure) is remediated in code by
  M14.4.1: sensitive filters live in PostgreSQL and never appear in a URL. The
  remaining production prerequisite is the Nginx/Gunicorn access-log review for
  legacy or third-party query strings.
- Retention scheduler, rate-limit TTL cleanup, run-log cleanup, runner
  credentials, monitoring, backup/restore, and the operational runbook are
  deployment prerequisites.
- Security-event IP/UA and identity snapshots are audit data and require an
  explicit data-classification/privacy sign-off.

#### Time sources (M14.5.1.1)

| Domain | Authoritative clock | Notes |
| --- | --- | --- |
| New `security_events.created_at` | PostgreSQL `now()` column default | No application timestamp is supplied. Historical timestamps are unchanged. |
| Retention cutoff | PostgreSQL `SELECT now()`, once per run | The same value is used for both scopes and every batch. |
| Retention hold `created_at`/`expires_at` | PostgreSQL `now()` plus a validated relative duration | Callers no longer submit an absolute expiry. |
| Hold active/eligibility check | PostgreSQL `now()` | Used by the service, trigger and retention function. |
| Run `started_at`/`finished_at` | PostgreSQL `clock_timestamp()` | Measures actual execution time rather than transaction start. |
| Rate-limit window/cooldown | Application UTC time | Not changed by this milestone; requires NTP on every app node. |
| Payment/order/manual-transfer expiry | Application UTC time | Requires NTP; outside the retention boundary. |
| Admin filter-state TTL | Application UTC time | Requires NTP; independent of retention. |

`now()`/`CURRENT_TIMESTAMP` is the transaction start time. It is deliberately
used for the retention cutoff so a long batch cannot drift. `clock_timestamp()`
moves with real time and is used only for run duration timestamps.
`statement_timestamp()` is not used for retention decisions.

The `CLOCK_SKEW_WARNING_SECONDS` diagnostic (default 120, allowed 1–86400)
compares application UTC with `SELECT now()`. A threshold breach logs a warning
and is reported by `security-event-retention check-clock`; it never changes a
clock, a session timezone, or fails the application/retention run. If the
diagnostic database is unavailable, the command reports that safely and exits
successfully.

The diagnostic currently reads `db.engine`, i.e. the application database. The
runner DSN (`SECURITY_EVENT_RETENTION_DATABASE_URL`) **must point to the same
PostgreSQL cluster/time source as the application database**. If the runner DSN
points to a different cluster, `check-clock` does not prove that the retention
cutoff and security-event timestamps share a clock. In that configuration,
clock alignment must be verified independently for each cluster. Keep NTP
configured and monitored on both the application hosts and the PostgreSQL hosts.

The runner DSN is supplied through
`SECURITY_EVENT_RETENTION_DATABASE_URL`, ideally from a secret manager. The
manual command is:

```bash
flask --app wsgi security-event-retention run \
  --batch-size 2000 --max-batches 20

# Advisory diagnostics:
flask --app wsgi security-event-retention check-clock
flask --app wsgi security-event-retention orphans --older-than-minutes 60
```

Exit status: `0` success, `2` partial (batch budget reached), `3` advisory lock
already held, `1` validation/store failure. There is no scheduler or background
worker. Production must invoke the command from an approved cron/systemd timer
using a non-login application account and a separately protected runner
credential; never put the database password on the command line. The
`check-clock` and `orphans` commands are operational diagnostics and do not
change the run exit contract.

Operational monitoring should track deleted rows, duration, success/failure
status, oldest event age against each cutoff, hold count, table size, dead
tuples/index bloat, consecutive failures, and `started` run rows older than the
orphan threshold. Alert on two consecutive failures, oldest event age beyond
cutoff + 7 days, repeated partial runs, or orphaned `started` rows.

Recommended deployment invocation:

- Run as a dedicated unprivileged OS service account, not the web process user.
- Load the runner DSN from a root-owned, mode-0600 environment file or secret
  manager; never place it in the command line, shell history, or application
  logs.
- Use a systemd timer or cron entry that invokes
  `flask --app wsgi security-event-retention run`.
- Capture stdout/stderr to the selected operational log or journald. The
  command prints only run_id, status, batch count and deleted count.
- Alert after two consecutive non-zero exits, a persistent partial status, or
  an oldest-event age beyond the relevant cutoff plus 7 days.
- A partial run is safe to rerun: the next invocation uses a new fixed cutoff
  and deletes the remaining eligible rows. A failed batch is rolled back and its
  `started` row is marked `failed` in a separate transaction; do not treat it as
  success. If the failure cannot be logged, the row stays `started` and appears
  in the orphan diagnostic.
- Manual execution must use the same runner credential and environment-loading
  procedure.

Superusers and sufficiently privileged table owners remain outside the
database-level retention boundary. This is not absolute immutability.


### M14.2 admin security-event viewer

The admin viewer is read-only and restricted to the `admin` role. The list page
does not display identifier hashes; the full `identifier_hash` is displayed
exclusively on an authorized event detail page. Detail pages use an explicit
per-event metadata display allowlist, render the User-Agent as escaped text, and
never traverse actor/subject relationships or join `users` or `audit_logs`.

List and detail responses set `Cache-Control: private, no-store`,
`Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex, nofollow`. The same
three headers are applied to every `/admin/*` response, including `303`
redirects and `400`/`403`/`404`/`405`/`429`/`500` responses.

#### Server-side security-event filter state (M14.4.1)

Sensitive filter values (`identifier_hash`, `request_id`, and the other viewer
filters) are never placed in a URL. The filter form POSTs to
`/admin/security-events/filters`; the server validates the values, stores them
in `admin_security_event_filter_states`, and returns `303` to
`/admin/security-events`.

- The browser holds only an opaque 256-bit token in the
  `utop14_se_filter_state` cookie (`HttpOnly`, `SameSite=Lax`,
  `Path=/admin/security-events`, `Secure` when the session cookie is secure).
- PostgreSQL stores only the SHA-256 digest of that token, the owning
  `admin_user_id`, and the validated JSONB payload. The raw token and the
  filters never appear in an access log or URL.
- Lookups require the digest, the authenticated admin id, and an unexpired
  `expires_at`. Another admin's token is ignored exactly like a missing state.
- The TTL is `ADMIN_SECURITY_EVENT_FILTER_TTL_MINUTES` (default 30, allowed
  1–240). Expired states are rejected at lookup time even if cleanup has not
  run.
- `flask admin-security-event-filters cleanup --limit N` deletes expired states
  in bounded batches. Security does not depend on this job; schedule it as an
  operational follow-up.
- Pagination carries only `?page=N`. Legacy URLs that contain filter parameters
  are redirected to a clean URL without echoing the values and **without
  clearing an active filter-state cookie**; the previously applied filters
  remain active after the redirect. Only the explicit clear-filter POST or
  logout removes state.
- Logout deletes the admin's stored states and clears the cookie. Multiple tabs
  share one state because the cookie is per-browser-session; applying a filter
  in one tab replaces the state seen by the other tabs on their next load.
- The login `next` target is stripped of `identifier_hash` and `request_id`, so
  an expired admin session cannot move sensitive filters into the login URL or
  the post-login redirect.

##### Trust boundary (accepted — M14.4.1.1 F-01)

`admin_security_event_filter_states` is inside the **database application-role
trust boundary**:

1. The `utop14_app` role holds `SELECT, INSERT, UPDATE, DELETE` on the table.
2. Per-admin authorization is enforced by the authenticated admin route and the
   service-layer ownership check (`admin_user_id`), not by the database.
3. The database does **not** provide row-level isolation between admins; there
   is no RLS policy on the table.
4. A compromised app role, SQL injection, or direct SQL with the app-role
   credential can read and modify every admin's filter state.
5. RLS keyed on a caller-controlled custom GUC is **not** a sufficient control
   against app-role compromise, because the app role can set that GUC itself.
6. The project therefore does **not** claim that filter state is protected from
   app-role compromise.
7. Per-user database roles or a trusted external authorization broker would be
   an architectural change; they are not part of this milestone.
8. This accepted boundary does not change the privileges of M13 `audit_logs`,
   M14.1 `security_events`, the M14.3 retention owner/runner, or the
   schema-owner/DBA trust boundary.

The stored filter payload contains the same identifier hashes, request IDs and
security-event metadata that the app role can already read from
`security_events`; the additional metadata is the admin-to-filter correlation.
That correlation is accepted under the existing single-application-role model.

The application never logs the token or the filter payload. The code-level
exposure is remediated here; **production deployment still requires** the
Nginx/Gunicorn access-log review so that legacy or third-party query strings are
not recorded. That infrastructure step is deferred and is not performed by this
repository milestone.

### M14.1 deployment checklist

1. Set `APP_ENV=production`.
2. Configure a dedicated, randomly generated `SECURITY_EVENT_HASH_KEY` with at
   least 32 bytes of UTF-8 key material.
3. Ensure the key differs from `SECRET_KEY`.
4. Never reuse the repository test key or any placeholder value.
5. Apply the security-event and rate-limit migrations from a controlled release
   job: `9b2d4e6f8a10`, `c4e7a1b9d2f6`, `e1b7c4a9d2f3`,
   `b4d8e2f7a1c9`, `d7c1a9e4b2f8`, `e3b9f1c7a2d4`, `c4a9e2f7b1d8`, and
   `f5d2b8c3e1a6`. Run migrations as the dedicated DDL/schema owner, not as the
   application role. If the retention functions are already owned by
   `utop14_retention_owner`, run the retention-function migrations as the
   DBA/superuser.
6. The request-ID index migration is non-concurrent. If `security_events`
   already contains production traffic, schedule index creation in a maintenance
   window or use a separately reviewed concurrent-index procedure.
7. Never downgrade `9b2d4e6f8a10` in production. Its downgrade drops the
   `security_events` table and destroys its history; do not run it without an
   approved backup and explicit authorization.
8. M14.1 does not complete production security hardening. Login rate limiting
   is implemented in M14.3.1/M14.3.2; security-event retention is implemented in
   M14.3.3. Permanent lockout, remember-cookie restoration, password reset/
   recovery event integration, and session anomaly detection remain deferred.

Password reset, account recovery, permanent lockout, session-anomaly detection,
remember-cookie restoration events, and automatic scheduler-driven retention
are not part of M14.1 or M14.3.2. M14.3.3 provides manual/bounded retention for
`security_events`; M13 `audit_logs` remain permanent.

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
7. Review Nginx and Gunicorn access-log configuration so admin security-event
   query strings (`request_id`, `identifier_hash`, actor/subject IDs) are not
   recorded in production logs. See the M14.2 viewer privacy note above.
8. Schedule the bounded authentication rate-limit cleanup command through an
   approved maintenance job until a scheduler is introduced. Login throttling is
   active in M14.3.2; deployment must also review rate-limit thresholds and
   access-log privacy.
9. Provision the dedicated retention roles from
   `scripts/security_event_retention_roles.sql` with a superuser, verify with
   `scripts/security_event_retention_verify.sql` as a PostgreSQL superuser, then
   schedule `security-event-retention run` using a protected runner DSN. Never
   run role provisioning from the application or a production migration.
10. Enforce the OPS-01 ownership model: the DDL/schema owner owns the database,
    schema, every application table and sequence, and trigger/helper functions;
    `utop14_app` is DML-only, owns nothing, has no role memberships, no function
    `EXECUTE`, no column-level grants, no `GRANT OPTION`, no database `CREATE`,
    no parameter `SET`/`ALTER SYSTEM`, and no persistent GUC other than
    `search_path=public, pg_catalog` in any database; `prune_security_events`
    stays owned by `utop14_retention_owner`. The app must have the complete
    least-privilege matrix, including `SELECT, INSERT` on `audit_logs` /
    `security_events`, `SELECT, INSERT, UPDATE, DELETE` on `auth_rate_limits`,
    and `USAGE, SELECT` on all application sequences it inserts into, but never
    `TRUNCATE`/`TRIGGER`/`REFERENCES`/`MAINTAIN`, sequence UPDATE, schema or
    database CREATE outside `public`, column-level grants, parameter ACLs, or
    ownership. Apply `scripts/security_event_retention_ownership_template.sql`
    only after DBA review, then run the provisioning and verification scripts.
    Follow the cluster-level GUC audit procedure for `postgresql.auto.conf`.
    Do not proceed to production if `security_event_retention_verify.sql` exits
    non-zero or if the app can disable an append-only trigger, assume a role,
    create objects in a non-application schema, create a schema, hold a column
    privilege, set a parameter, or retain an unapproved role/database GUC in
    any database.

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
