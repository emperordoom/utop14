-- UTOP14 comprehensive application ownership template (OPS-01).
--
-- THIS IS A REVIEW-AND-ADAPT TEMPLATE.  It is NOT run by migrations or by the
-- application.  A DBA must review it, replace the placeholders, and run it as a
-- superuser during a controlled change window.
--
-- Goal: the application login role is DML-only.  It must not own the database,
-- schema, application tables, sequences, or privileged functions.  The
-- retention function stays owned by utop14_retention_owner; the trigger/helper
-- functions belong to the DDL/schema owner.
--
-- Placeholders:
--   <schema_owner>   dedicated DDL/schema-owner role (not utop14_app)
--   <database_name>  the application database
--
-- Safe execution order for a new or existing installation:
--   1. Run all Alembic migrations as <schema_owner>/DBA.
--   2. Run this ownership template as a superuser (review first).
--   3. Run scripts/security_event_retention_roles.sql as a superuser.
--   4. Run scripts/security_event_retention_verify.sql as the DBA; it must
--      exit 0.
--
-- Do not run this against production without change approval and a backup.

-- 1. Database and schema ownership.
ALTER DATABASE <database_name> OWNER TO <schema_owner>;
ALTER SCHEMA public OWNER TO <schema_owner>;

-- 2. Complete application table ownership inventory.
--    Alembic metadata is included so the app cannot own it either.
ALTER TABLE IF EXISTS public.alembic_version OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.users OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.audit_logs OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.security_events OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.auth_rate_limits OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.security_event_retention_holds OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.security_event_retention_runs OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.categories OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.products OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.product_variants OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.product_images OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.carts OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.cart_items OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.orders OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.order_items OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.payments OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.payment_proofs OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.product_reviews OWNER TO <schema_owner>;

-- 3. Complete sequence ownership inventory.  These are the SERIAL sequences
--    for every application table that has one.  auth_rate_limits uses a
--    composite primary key and has no sequence.
ALTER SEQUENCE IF EXISTS public.users_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.audit_logs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.security_events_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.security_event_retention_holds_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.security_event_retention_runs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.categories_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.products_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.product_variants_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.product_images_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.carts_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.cart_items_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.orders_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.order_items_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.payments_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.payment_proofs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.product_reviews_id_seq OWNER TO <schema_owner>;

-- 4. Trigger/helper functions belong to the DDL/schema owner.  They are not
--    SECURITY DEFINER and hold no elevated privileges.
ALTER FUNCTION public.audit_logs_reject_mutation() OWNER TO <schema_owner>;
ALTER FUNCTION public.security_events_reject_mutation() OWNER TO <schema_owner>;
ALTER FUNCTION public.security_event_retention_holds_lock() OWNER TO <schema_owner>;

-- 5. Do NOT transfer the SECURITY DEFINER retention entry point:
--    public.prune_security_events must stay owned by
--    utop14_retention_owner.  Role provisioning sets this ownership explicitly.

-- 6. Remove schema CREATE from untrusted roles.  USAGE is retained.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM utop14_app;

-- 7. Verify the intended model.  This script must exit 0.
--    \i scripts/security_event_retention_verify.sql
