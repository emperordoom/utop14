-- UTOP14 security-event retention ownership template (OPS-01).
--
-- THIS IS A REVIEW-AND-ADAPT TEMPLATE.  It is NOT run by migrations or by the
-- application.  A DBA must review it, replace the placeholders, and run it as a
-- superuser during a controlled change window.
--
-- Goal: the application login role must be a DML-only role.  It must not own
-- the database, schema, security tables, sequences, or functions.  The
-- retention function must remain owned by utop14_retention_owner; the
-- retention trigger/helper functions belong to the DDL/schema owner.
--
-- Placeholders:
--   <schema_owner>   dedicated DDL/schema-owner role (not utop14_app)
--   <database_name>  the application database
--
-- After running this template, re-run:
--   scripts/security_event_retention_roles.sql   (grants)
--   scripts/security_event_retention_verify.sql  (must exit 0)
--
-- Do not run this against production without change approval and a backup.

-- 1. Database and schema ownership.
ALTER DATABASE <database_name> OWNER TO <schema_owner>;
ALTER SCHEMA public OWNER TO <schema_owner>;

-- 2. Security and retention table ownership.
ALTER TABLE IF EXISTS public.security_events OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.security_event_retention_holds OWNER TO <schema_owner>;
ALTER TABLE IF EXISTS public.security_event_retention_runs OWNER TO <schema_owner>;

-- 3. Owned sequences (SERIAL/IDENTITY sequences follow the table in most
--    cases, but make the ownership explicit for verification).
ALTER SEQUENCE IF EXISTS public.security_events_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.security_event_retention_holds_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE IF EXISTS public.security_event_retention_runs_id_seq OWNER TO <schema_owner>;

-- 4. Trigger/helper functions belong to the DDL/schema owner.
ALTER FUNCTION IF EXISTS public.security_events_reject_mutation() OWNER TO <schema_owner>;
ALTER FUNCTION IF EXISTS public.security_event_retention_holds_lock() OWNER TO <schema_owner>;

-- 5. Do NOT transfer the SECURITY DEFINER retention entry point.  It must stay
--    owned by utop14_retention_owner so the append-only trigger can identify
--    the only permitted DELETE execution context.  The role provisioning script
--    sets this ownership explicitly.

-- 6. Remove schema CREATE from untrusted roles.  USAGE is retained.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM utop14_app;

-- 7. Verify the intended model.  This script must exit 0.
--    \i scripts/security_event_retention_verify.sql
