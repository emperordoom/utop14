-- UTOP14 security-event retention role provisioning.
--
-- Run as a PostgreSQL superuser or a role allowed to create roles and change
-- function ownership. Never run this against production without a separate
-- change approval and secret-management procedure.
--
-- Replace utop14_app with the application login role used by the deployment.
-- Create utop14_retention_runner as NOLOGIN and use a separately controlled
-- operational login/credential to SET ROLE or connect as an approved runner.
-- Do not put passwords in command-line arguments or this file.

CREATE ROLE utop14_retention_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

CREATE ROLE utop14_retention_runner
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- The application role must not be a member of either retention role.
REVOKE utop14_retention_owner FROM utop14_app;
REVOKE utop14_retention_runner FROM utop14_app;

GRANT USAGE ON SCHEMA public TO utop14_retention_owner;
GRANT USAGE ON SCHEMA public TO utop14_retention_runner;

-- The owner has only the table access required by the SECURITY DEFINER
-- function: read/delete events, read active holds, and append run records.
GRANT SELECT, DELETE ON security_events TO utop14_retention_owner;
GRANT SELECT ON security_event_retention_holds TO utop14_retention_owner;
GRANT SELECT, INSERT ON security_event_retention_runs TO utop14_retention_owner;
GRANT USAGE, SELECT ON SEQUENCE security_event_retention_runs_id_seq
    TO utop14_retention_owner;

-- The runner can invoke only the approved entry point and append failure or
-- partial run records. It has no direct event DELETE/UPDATE/TRUNCATE privilege.
GRANT EXECUTE ON FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    TO utop14_retention_runner;
GRANT SELECT, INSERT ON security_event_retention_runs TO utop14_retention_runner;
GRANT USAGE, SELECT ON SEQUENCE security_event_retention_runs_id_seq
    TO utop14_retention_runner;

-- Application-role hold management grants; no event deletion or function
-- execution is granted to the app role.  INSERT on security_events is required
-- by the M14.1 application event writer and is not a retention privilege.
GRANT SELECT, INSERT ON security_events TO utop14_app;
-- The M14.1 event writer relies on the SERIAL identity sequence for
-- security_events.id.  The sequence stays owned by the schema/DDL owner; the
-- app receives only USAGE/SELECT (never UPDATE or ownership).
GRANT USAGE, SELECT ON SEQUENCE security_events_id_seq TO utop14_app;
-- UPDATE is required to replace an already-expired hold.  The
-- security_event_retention_holds_lock trigger rejects direct expiry or
-- shortening of an active hold and serializes every hold write with cleanup.
GRANT SELECT, INSERT, UPDATE ON security_event_retention_holds TO utop14_app;
GRANT USAGE, SELECT ON SEQUENCE security_event_retention_holds_id_seq
    TO utop14_app;

-- The function must be owned by the retention owner so the append-only trigger
-- can identify the only permitted DELETE execution context.
ALTER FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    OWNER TO utop14_retention_owner;

REVOKE ALL ON FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    public.prune_security_events(text, timestamptz, integer, uuid, integer)
    TO utop14_retention_runner;

-- Trigger-only helper.  It is not SECURITY DEFINER and has no elevated
-- privileges; the grant exists because the hardening migration revoked PUBLIC.
GRANT EXECUTE ON FUNCTION public.security_event_retention_holds_lock()
    TO utop14_app, utop14_retention_owner, utop14_retention_runner;

-- Explicitly keep dangerous privileges away from retention roles.
REVOKE UPDATE, TRUNCATE ON security_events FROM utop14_retention_owner;
REVOKE UPDATE, TRUNCATE ON security_events FROM utop14_retention_runner;
REVOKE DELETE, UPDATE, TRUNCATE ON security_events FROM utop14_retention_runner;
