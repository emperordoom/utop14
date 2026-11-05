-- UTOP14 application and retention role provisioning.
--
-- Run as a PostgreSQL superuser/DBA after:
--   1. all Alembic migrations have been applied by the DDL/schema owner;
--   2. scripts/security_event_retention_ownership_template.sql has been
--      reviewed and applied so the schema/DDL owner owns every application
--      table and sequence.
-- Never run this against production without change approval and a backup.
--
-- This script manages grants only.  It does not create the schema/DDL owner,
-- run migrations, or transfer ownership.  The application role must already
-- exist (replace utop14_app with the deployment login role if different).
--
-- Least-privilege model:
--   * utop14_app: DML only; no TRUNCATE/TRIGGER/REFERENCES, no ownership, no
--     retention function execution, no retention run-log access.
--   * utop14_retention_owner: NOLOGIN; owns the SECURITY DEFINER retention
--     function; can read/delete events, read holds, append run rows.
--   * utop14_retention_runner: LOGIN; only the retention function entry point
--     plus run-log append/read.
-- Do not put passwords in command-line arguments or this file.

CREATE ROLE utop14_retention_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- The runner is LOGIN because the operational CLI connects with a dedicated
-- DSN.  Its password/credential must come from a secret manager, never from
-- this file or a command line.
CREATE ROLE utop14_retention_runner
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- The application role must not be a member of either retention role.
REVOKE utop14_retention_owner FROM utop14_app;
REVOKE utop14_retention_runner FROM utop14_app;

-- Schema access: usage only, never CREATE.
GRANT USAGE ON SCHEMA public
    TO utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE CREATE ON SCHEMA public
    FROM utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Application role: reset then grant the complete least-privilege matrix.
-- The explicit REVOKE ALL removes stale broad grants from earlier
-- deployments; the subsequent grants are the authoritative matrix.
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM utop14_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM utop14_app;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM utop14_app;

-- Read/write application tables (no hard-delete paths in the services).
GRANT SELECT, INSERT, UPDATE ON
    public.users,
    public.categories,
    public.products,
    public.product_variants,
    public.carts,
    public.orders,
    public.payments,
    public.payment_proofs,
    public.product_reviews,
    public.security_event_retention_holds
    TO utop14_app;

-- Append-only or insert-only application tables.
-- audit_logs and security_events: app may append and read, never mutate.
-- order_items: immutable checkout snapshots; insert and read only.
GRANT SELECT, INSERT ON
    public.audit_logs,
    public.security_events,
    public.order_items
    TO utop14_app;

-- Tables requiring DELETE:
--   auth_rate_limits: successful-login reset and TTL cleanup.
--   cart_items: remove one line / clear cart.
--   product_images: admin gallery image deletion.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    public.auth_rate_limits,
    public.cart_items,
    public.product_images
    TO utop14_app;

-- Deliberately no app privileges:
--   public.alembic_version            (migration metadata)
--   public.security_event_retention_runs (owner/runner only)
--   public.security_event_retention_runs_id_seq (owner/runner only)

-- App sequences: every table the app inserts into has a SERIAL sequence.
-- auth_rate_limits has no sequence; retention runs are excluded.
GRANT USAGE, SELECT ON SEQUENCE
    public.users_id_seq,
    public.audit_logs_id_seq,
    public.security_events_id_seq,
    public.security_event_retention_holds_id_seq,
    public.categories_id_seq,
    public.products_id_seq,
    public.product_variants_id_seq,
    public.product_images_id_seq,
    public.carts_id_seq,
    public.cart_items_id_seq,
    public.orders_id_seq,
    public.order_items_id_seq,
    public.payments_id_seq,
    public.payment_proofs_id_seq,
    public.product_reviews_id_seq
    TO utop14_app;

-- The hold-lock trigger helper is the only function the app may execute.
-- It is trigger-only and not SECURITY DEFINER.
GRANT EXECUTE ON FUNCTION public.security_event_retention_holds_lock()
    TO utop14_app;

-- Defence-in-depth revokes: remove dangerous privileges even if an earlier
-- deployment granted them.  The app must never mutate append-only history.
REVOKE TRUNCATE, TRIGGER, REFERENCES ON ALL TABLES IN SCHEMA public
    FROM utop14_app;
REVOKE UPDATE, DELETE ON
    public.audit_logs,
    public.security_events,
    public.security_event_retention_runs,
    public.alembic_version,
    public.order_items
    FROM utop14_app;
REVOKE INSERT, UPDATE, DELETE ON public.alembic_version FROM utop14_app;
REVOKE DELETE ON
    public.users,
    public.categories,
    public.products,
    public.product_variants,
    public.carts,
    public.orders,
    public.payments,
    public.payment_proofs,
    public.product_reviews,
    public.security_event_retention_holds
    FROM utop14_app;
REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public FROM utop14_app;

-- ---------------------------------------------------------------------------
-- Retention owner: reset then grant only the retention boundary.
-- ---------------------------------------------------------------------------
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;

GRANT SELECT, DELETE ON public.security_events TO utop14_retention_owner;
GRANT SELECT ON public.security_event_retention_holds TO utop14_retention_owner;
GRANT SELECT, INSERT ON public.security_event_retention_runs TO utop14_retention_owner;
GRANT USAGE, SELECT ON SEQUENCE public.security_event_retention_runs_id_seq
    TO utop14_retention_owner;

GRANT SELECT, INSERT ON public.security_event_retention_runs TO utop14_retention_runner;
GRANT USAGE, SELECT ON SEQUENCE public.security_event_retention_runs_id_seq
    TO utop14_retention_runner;

-- The function must be owned by the retention owner so the append-only trigger
-- can identify the only permitted DELETE execution context.  The runner can
-- execute only this entry point.
ALTER FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    OWNER TO utop14_retention_owner;

REVOKE ALL ON FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    TO utop14_retention_runner;

-- Trigger/helper function is trigger-only and not SECURITY DEFINER.  PUBLIC
-- must not execute it directly; the app receives EXECUTE above so its hold
-- writes can fire the trigger.
REVOKE ALL ON FUNCTION public.security_event_retention_holds_lock() FROM PUBLIC;

-- The append-only trigger functions are trigger-only and not SECURITY DEFINER.
-- The app cannot UPDATE/DELETE audit_logs or security_events, so it does not
-- need EXECUTE on them.  Revoke the default PUBLIC grant and any app grant.
REVOKE ALL ON FUNCTION public.audit_logs_reject_mutation()
    FROM PUBLIC, utop14_app;
REVOKE ALL ON FUNCTION public.security_events_reject_mutation()
    FROM PUBLIC, utop14_app;

-- Explicitly keep dangerous privileges away from the retention roles.
REVOKE UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_owner;
REVOKE UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_runner;
REVOKE DELETE, UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_runner;
REVOKE TRUNCATE, TRIGGER, REFERENCES ON ALL TABLES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;
REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;
