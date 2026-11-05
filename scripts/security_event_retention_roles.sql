-- UTOP14 application and retention role provisioning.
--
-- Run as a PostgreSQL superuser/DBA after:
--   1. all Alembic migrations have been applied by the DDL/schema owner;
--   2. scripts/security_event_retention_ownership_template.sql has been
--      reviewed and applied so the schema/DDL owner owns every application
--      table and sequence.
-- Never run this against production without change approval and a backup.
--
-- Supported PostgreSQL: 16 or newer for membership option columns
-- (inherit_option/set_option).  Membership options are read through to_jsonb
-- and a missing option is treated as TRUE, so older catalogs are handled
-- conservatively.
--
-- This script manages roles and grants only.  It does not create the
-- schema/DDL owner, run migrations, or transfer table/sequence ownership.
-- The application role must already exist (replace utop14_app with the
-- deployment login role if different).
--
-- Least-privilege model:
--   * utop14_app: DML only; no TRUNCATE/TRIGGER/REFERENCES/MAINTAIN, no
--     ownership, no retention function execution, no retention run-log access,
--     no CREATE or USAGE outside public, no database CREATE, no column-level
--     grants or GRANT OPTION, no parameter SET/ALTER SYSTEM, no role
--     memberships, and only the approved search_path GUC.
--   * utop14_retention_owner: NOLOGIN; owns the SECURITY DEFINER retention
--     function; can read/delete events, read holds, append run rows.
--   * utop14_retention_runner: LOGIN; only the retention function entry point
--     plus run-log append/read.
-- Do not put passwords in command-line arguments or this file.  This script
-- never reads or changes role passwords.
--
-- Reliability model:
--   * Preflight runs before any role/grant change and fails closed on missing
--     objects, wrong ownership, an unexpected migration head, unexpected
--     schemas/types/extensions/objects, dangerous role attributes, dangerous
--     custom default ACLs, or reverse memberships.
--   * The full table grant reset removes column ACLs and all table privileges,
--     including PG17+ MAINTAIN.  Database-level CREATE is revoked from managed
--     roles and PUBLIC, parameter SET/ALTER SYSTEM grants are revoked, all
--     persistent role/database GUCs for managed roles are reset, and the app
--     search_path is set to public, pg_catalog.
--   * The whole script runs in one transaction.  CREATE ROLE, ALTER ROLE,
--     GRANT/REVOKE and ALTER FUNCTION ... OWNER are transactional on the
--     supported PostgreSQL versions, so a mid-script failure rolls back
--     completely and a rerun starts from the previous state.
--   * Role creation is guarded and role attributes are reconciled explicitly,
--     so a second run succeeds and produces the same state.
--   * Every forward membership of a managed role is removed unless it is in
--     the explicit (currently empty) allowlist.  Reverse memberships fail the
--     preflight and require manual review.  Recovery for a reverse membership
--     is documented in README.md (OPS-01).
--
-- Execution order: migrations -> ownership template -> this script -> verify.

\set ON_ERROR_STOP on
\pset pager off

BEGIN;

-- ---------------------------------------------------------------------------
-- Preflight 1: required roles and incompatible role attributes
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_schema_owner') THEN
        RAISE EXCEPTION 'FAIL: utop14_schema_owner is missing; run the ownership template prerequisites first';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_app') THEN
        RAISE EXCEPTION 'FAIL: utop14_app is missing; create the application login role first';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_app' AND rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app must be a LOGIN role';
    END IF;

    FOR r IN
        SELECT rolname, rolsuper, rolcreatedb, rolcreaterole,
               rolreplication, rolbypassrls
        FROM pg_catalog.pg_roles
        WHERE rolname IN ('utop14_app',
                          'utop14_retention_owner',
                          'utop14_retention_runner')
    LOOP
        IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole
           OR r.rolreplication OR r.rolbypassrls THEN
            RAISE EXCEPTION
                'FAIL: role % has incompatible privileged attributes; run ALTER ROLE % NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS, then rerun this script',
                r.rolname, pg_catalog.quote_ident(r.rolname);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight 2: database/schema ownership and migration head
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_owner text;
    v_head text;
    v_rows integer;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(datdba) INTO v_owner
    FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database();
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION
            'FAIL: database owner=% (expected utop14_schema_owner); apply the ownership template first',
            v_owner;
    END IF;

    SELECT nspowner::regrole::text INTO v_owner
    FROM pg_catalog.pg_namespace WHERE nspname = 'public';
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION
            'FAIL: schema public owner=% (expected utop14_schema_owner); apply the ownership template first',
            v_owner;
    END IF;

    IF pg_catalog.to_regclass('public.alembic_version') IS NULL THEN
        RAISE EXCEPTION 'FAIL: public.alembic_version is missing; run migrations first';
    END IF;
    SELECT pg_catalog.count(*), pg_catalog.max(version_num) INTO v_rows, v_head
    FROM public.alembic_version;
    IF v_rows <> 1 THEN
        RAISE EXCEPTION 'FAIL: alembic_version must contain exactly one row (found %)', v_rows;
    END IF;
    -- Update this expected head only together with a reviewed migration.  A
    -- mismatched head must never silently provision a partially migrated DB.
    IF v_head IS DISTINCT FROM 'e3b9f1c7a2d4' THEN
        RAISE EXCEPTION
            'FAIL: database migration head=% (expected e3b9f1c7a2d4); review and update this preflight after applying the approved migration',
            v_head;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight 3: extension/schema/type/object inventory and ownership
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    expected_schemas text[] := ARRAY['public'];
    expected_extensions text[] := ARRAY['plpgsql'];
    expected_tables text[] := ARRAY[
        'alembic_version', 'audit_logs', 'auth_rate_limits', 'cart_items',
        'carts', 'categories', 'order_items', 'orders', 'payment_proofs',
        'payments', 'product_images', 'product_reviews', 'product_variants',
        'products', 'security_event_retention_holds',
        'security_event_retention_runs', 'security_events', 'users'
    ];
    expected_sequences text[] := ARRAY[
        'audit_logs_id_seq', 'cart_items_id_seq', 'carts_id_seq',
        'categories_id_seq', 'order_items_id_seq', 'orders_id_seq',
        'payment_proofs_id_seq', 'payments_id_seq', 'product_images_id_seq',
        'product_reviews_id_seq', 'product_variants_id_seq', 'products_id_seq',
        'security_event_retention_holds_id_seq',
        'security_event_retention_runs_id_seq', 'security_events_id_seq',
        'users_id_seq'
    ];
    expected_functions text[] := ARRAY[
        'public.audit_logs_reject_mutation()',
        'public.security_events_reject_mutation()',
        'public.security_event_retention_holds_lock()',
        'public.prune_security_events(text, timestamptz, integer, uuid, integer)'
    ];
    expected_triggers text[] := ARRAY[
        'audit_logs_append_only', 'security_event_retention_holds_lock',
        'security_events_append_only'
    ];
    r record;
    fn text;
    v_extra text[];
    v_owner text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'plpgsql') THEN
        RAISE EXCEPTION 'FAIL: required extension plpgsql is missing';
    END IF;
    SELECT pg_catalog.array_agg(extname ORDER BY extname) INTO v_extra
    FROM pg_catalog.pg_extension WHERE NOT (extname = ANY (expected_extensions));
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried extensions %; review them and update the provisioning allowlist',
            v_extra;
    END IF;

    SELECT pg_catalog.array_agg(n.nspname ORDER BY n.nspname) INTO v_extra
    FROM pg_catalog.pg_namespace n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_namespace'::regclass
            AND d.objid = n.oid
            AND d.deptype = 'e'
      )
      AND NOT (n.nspname = ANY (expected_schemas));
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried non-system schemas %; review them and update the provisioning allowlist',
            v_extra;
    END IF;

    SELECT pg_catalog.array_agg(pg_catalog.format('%I.%I', n.nspname, t.typname) ORDER BY 1) INTO v_extra
    FROM pg_catalog.pg_type t
    JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = ANY (expected_schemas)
      AND t.typtype IN ('b', 'c', 'd', 'e', 'r', 'm')
      AND NOT (t.typtype = 'b' AND t.typelem <> 0 AND t.typlen = -1)
      AND NOT (
          t.typtype = 'c'
          AND EXISTS (
              SELECT 1 FROM pg_catalog.pg_class c
              WHERE c.oid = t.typrelid AND c.relkind IN ('r', 'p', 'f')
          )
      )
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_type'::regclass
            AND d.objid = t.oid
            AND d.deptype = 'e'
      );
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried user-defined types/domains %; update the provisioning inventory and privilege model',
            v_extra;
    END IF;

    SELECT pg_catalog.array_agg(t) INTO v_extra
    FROM pg_catalog.unnest(expected_tables) t
    WHERE pg_catalog.to_regclass(pg_catalog.format('public.%I', t)) IS NULL;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected tables %', v_extra;
    END IF;
    SELECT pg_catalog.array_agg(s) INTO v_extra
    FROM pg_catalog.unnest(expected_sequences) s
    WHERE pg_catalog.to_regclass(pg_catalog.format('public.%I', s)) IS NULL;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected sequences %', v_extra;
    END IF;

    FOR r IN
        SELECT c.relname, c.relkind, pg_catalog.pg_get_userbyid(c.relowner) AS owner,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_depend d
                   WHERE d.classid = 'pg_catalog.pg_class'::regclass
                     AND d.objid = c.oid
                     AND d.deptype = 'e'
               ) AS extension_owned
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f', 'S')
    LOOP
        CONTINUE WHEN r.extension_owned;
        IF r.relkind = 'S' AND NOT (r.relname = ANY (expected_sequences)) THEN
            RAISE EXCEPTION 'FAIL: uninventoried sequence %', r.relname;
        END IF;
        IF r.relkind <> 'S' AND NOT (r.relname = ANY (expected_tables)) THEN
            RAISE EXCEPTION 'FAIL: uninventoried table %', r.relname;
        END IF;
        IF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION
                'FAIL: % owner=% (expected utop14_schema_owner); apply the ownership template first',
                r.relname, r.owner;
        END IF;
    END LOOP;

    FOREACH fn IN ARRAY expected_functions LOOP
        IF pg_catalog.to_regprocedure(fn) IS NULL THEN
            RAISE EXCEPTION 'FAIL: required function % is missing; run migrations first', fn;
        END IF;
    END LOOP;
    SELECT pg_catalog.array_agg(p.proname ORDER BY p.proname) INTO v_extra
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT (p.proname = ANY (ARRAY[
          'audit_logs_reject_mutation', 'prune_security_events',
          'security_event_retention_holds_lock', 'security_events_reject_mutation'
      ]))
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
      );
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried functions/procedures %', v_extra;
    END IF;

    FOR r IN
        SELECT p.proname, pg_catalog.pg_get_userbyid(p.proowner) AS owner
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_proc'::regclass
                AND d.objid = p.oid
                AND d.deptype = 'e'
          )
    LOOP
        IF r.proname = 'prune_security_events' THEN
            -- Before the first provisioning run the migration/DDL role owns
            -- the function; after a successful run the retention owner does.
            IF r.owner NOT IN ('utop14_schema_owner', 'utop14_retention_owner') THEN
                RAISE EXCEPTION 'FAIL: prune_security_events owner=%', r.owner;
            END IF;
        ELSIF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: helper function % owner=%', r.proname, r.owner;
        END IF;
    END LOOP;

    SELECT pg_catalog.array_agg(t) INTO v_extra
    FROM pg_catalog.unnest(expected_triggers) t
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger tr
        JOIN pg_catalog.pg_class c ON c.oid = tr.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND tr.tgname = t AND NOT tr.tgisinternal
    );
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected triggers %', v_extra;
    END IF;
    SELECT pg_catalog.array_agg(tr.tgname ORDER BY tr.tgname) INTO v_extra
    FROM pg_catalog.pg_trigger tr
    JOIN pg_catalog.pg_class c ON c.oid = tr.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY (expected_tables)
      AND NOT tr.tgisinternal
      AND NOT (tr.tgname = ANY (expected_triggers));
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried triggers %', v_extra;
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('v', 'm')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    ) THEN
        RAISE EXCEPTION 'FAIL: unexpected view/materialized view; update the provisioning inventory';
    END IF;

    SELECT pg_catalog.pg_get_userbyid(datdba) INTO v_owner
    FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database();
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION 'FAIL: database owner=%', v_owner;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight 4: dangerous custom default ACLs
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT d.defaclrole::regrole::text AS owner_role,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE a.grantee::regrole::text END AS grantee,
               a.privilege_type
        FROM pg_catalog.pg_default_acl d,
             pg_catalog.aclexplode(d.defaclacl) a
        WHERE d.defaclrole IN (pg_catalog.to_regrole('utop14_app'),
                               pg_catalog.to_regrole('utop14_retention_owner'),
                               pg_catalog.to_regrole('utop14_retention_runner'))
           OR a.grantee IN (pg_catalog.to_regrole('utop14_app'),
                            pg_catalog.to_regrole('utop14_retention_owner'),
                            pg_catalog.to_regrole('utop14_retention_runner'))
           OR a.grantee = 0
    LOOP
        RAISE EXCEPTION
            'FAIL: dangerous custom default privilege % on % grants to %; remove it with ALTER DEFAULT PRIVILEGES before rerunning',
            r.privilege_type, r.owner_role, r.grantee;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight 5: reverse memberships (manual review required)
--
-- Forward memberships (a managed role is a member of another role) are
-- reconciled below by REVOKE.  Reverse memberships (another role can assume a
-- managed role) are not removed automatically because they may be an
-- intentional infrastructure dependency; fail and document the review.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_reverse_member text;
    v_reverse_role text;
BEGIN
    SELECT r.rolname, g.rolname INTO v_reverse_member, v_reverse_role
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles r ON r.oid = m.member
    JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
    WHERE g.rolname IN ('utop14_app',
                        'utop14_retention_owner',
                        'utop14_retention_runner')
      AND r.rolname NOT IN ('utop14_app',
                            'utop14_retention_owner',
                            'utop14_retention_runner')
    LIMIT 1;
    IF v_reverse_member IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: reverse membership % -> % lets another role assume a managed role; run REVOKE % FROM % manually, document the dependency, then rerun',
            v_reverse_member, v_reverse_role,
            pg_catalog.quote_ident(v_reverse_role), pg_catalog.quote_ident(v_reverse_member);
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight 6: parameter ACL support, database-wide GUCs, schema-owner GUCs
--
-- Database-wide and schema-owner settings are never silently changed.  They
-- must be reconciled by the DBA before provisioning.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_entry text;
    v_sensitive text[] := ARRAY[
        'shared_preload_libraries',
        'session_preload_libraries',
        'local_preload_libraries',
        'log_statement',
        'log_min_duration_statement',
        'log_min_error_statement',
        'log_min_messages',
        'log_destination',
        'logging_collector',
        'log_connections',
        'log_disconnections',
        'log_duration',
        'log_hostname',
        'log_line_prefix',
        'log_statement_sample_rate',
        'log_transaction_sample_rate',
        'search_path'
    ];
BEGIN
    IF pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NULL
       OR pg_catalog.to_regprocedure(
           'pg_catalog.has_parameter_privilege(name,text,text)'
       ) IS NULL
       OR pg_catalog.to_regclass('pg_catalog.pg_settings') IS NULL
       OR pg_catalog.to_regclass('pg_catalog.pg_file_settings') IS NULL THEN
        RAISE EXCEPTION
            'FAIL: required parameter/GUC catalog support is unavailable; cannot provision safely';
    END IF;

    -- Database-wide settings in ANY database are DBA-reconciled, not reset.
    FOR r IN
        SELECT coalesce(d.datname, 'ALL DATABASES') AS dbname,
               s.setdatabase,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole = 0
    LOOP
        IF r.setconfig IS NOT NULL
           AND pg_catalog.array_length(r.setconfig, 1) > 0 THEN
            RAISE EXCEPTION
                'FAIL: database-wide GUC % in % (setdatabase=%) requires DBA reconciliation before provisioning; this script will not modify unrelated roles',
                r.setconfig, r.dbname, r.setdatabase;
        END IF;
    END LOOP;

    -- Schema-owner role-level settings: search_path only.
    FOR r IN
        SELECT rolconfig
        FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_schema_owner'
    LOOP
        IF r.rolconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.rolconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: utop14_schema_owner has unapproved role-level GUC %; DBA reconciliation required before provisioning',
                        v_entry;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- Schema-owner database-specific settings in ANY database:
    -- search_path only.
    FOR r IN
        SELECT coalesce(d.datname, 'UNKNOWN DATABASE') AS dbname,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole = 'utop14_schema_owner'::regrole
          AND s.setdatabase <> 0
    LOOP
        IF r.setconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.setconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: utop14_schema_owner has unapproved database-specific GUC % in %; DBA reconciliation required before provisioning',
                        v_entry, r.dbname;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- postgresql.auto.conf is the ALTER SYSTEM persistence path.  Refuse to
    -- provision while sensitive cluster settings remain there.
    FOR r IN
        SELECT name, setting, sourcefile, pending_restart
        FROM pg_catalog.pg_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile IS NOT NULL
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: sensitive cluster GUC %=% remains in postgresql.auto.conf (%); pending_restart=% requires DBA reconciliation before provisioning',
            r.name, r.setting, r.sourcefile, r.pending_restart;
    END LOOP;
    FOR r IN
        SELECT sourcefile, name, setting, applied, error
        FROM pg_catalog.pg_file_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: postgresql.auto.conf contains sensitive GUC %=% (%); applied=%, error=% requires DBA reconciliation before provisioning',
            r.name, r.setting, r.sourcefile, r.applied, r.error;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 1. Guarded role creation and explicit attribute reconciliation
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_retention_owner') THEN
        CREATE ROLE utop14_retention_owner
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
            NOREPLICATION NOBYPASSRLS;
    END IF;
    -- The runner is LOGIN because the operational CLI connects with a
    -- dedicated DSN.  Its password/credential must come from a secret manager,
    -- never from this file or a command line.  CREATE ROLE does not set a
    -- password; this script never changes one.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_retention_runner') THEN
        CREATE ROLE utop14_retention_runner
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
            NOREPLICATION NOBYPASSRLS;
    END IF;
END $$;

ALTER ROLE utop14_retention_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
    NOREPLICATION NOBYPASSRLS;
ALTER ROLE utop14_retention_runner
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
    NOREPLICATION NOBYPASSRLS;
-- Keep the already-existing app login role's LOGIN capability, but reconcile
-- the privilege-relevant attributes.  Passwords are untouched.
ALTER ROLE utop14_app
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
    NOREPLICATION NOBYPASSRLS;
-- Remove all persistent role-level GUCs for managed roles, then remove any
-- database-specific settings for those roles in EVERY non-template database.
-- The app search_path is applied explicitly afterwards; existing pooled
-- connections keep their old session setting until they reconnect, so recycle
-- pools after provisioning.
ALTER ROLE utop14_app RESET ALL;
ALTER ROLE utop14_retention_owner RESET ALL;
ALTER ROLE utop14_retention_runner RESET ALL;
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT datname
        FROM pg_catalog.pg_database
        WHERE NOT datistemplate
    LOOP
        EXECUTE pg_catalog.format(
            'ALTER ROLE %I IN DATABASE %I RESET ALL',
            'utop14_app', r.datname
        );
        EXECUTE pg_catalog.format(
            'ALTER ROLE %I IN DATABASE %I RESET ALL',
            'utop14_retention_owner', r.datname
        );
        EXECUTE pg_catalog.format(
            'ALTER ROLE %I IN DATABASE %I RESET ALL',
            'utop14_retention_runner', r.datname
        );
    END LOOP;
END $$;
ALTER ROLE utop14_app SET search_path = public, pg_catalog;

-- Reconcile parameter SET/ALTER SYSTEM grants for managed roles and PUBLIC.
-- Grants to unrelated DBA/custom roles are left untouched.  CASCADE removes
-- privileges that a managed role or PUBLIC delegated to other roles; those
-- grants are derived from the unauthorized grant.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT p.parname,
               a.grantee,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee_name,
               a.privilege_type
        FROM pg_catalog.pg_parameter_acl p
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a
        WHERE a.grantee = 0
           OR a.grantee IN ('utop14_app'::regrole,
                            'utop14_retention_owner'::regrole,
                            'utop14_retention_runner'::regrole,
                            'utop14_schema_owner'::regrole)
    LOOP
        IF r.grantee = 0 THEN
            EXECUTE pg_catalog.format(
                'REVOKE %s ON PARAMETER %I FROM PUBLIC CASCADE',
                r.privilege_type, r.parname
            );
        ELSE
            EXECUTE pg_catalog.format(
                'REVOKE %s ON PARAMETER %I FROM %I CASCADE',
                r.privilege_type, r.parname, r.grantee_name
            );
        END IF;
        RAISE NOTICE 'REVOKED parameter privilege % on % from %',
            r.privilege_type, r.parname, r.grantee_name;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Database-level CREATE: app/retention roles and PUBLIC must not be able
-- to create schemas.  CONNECT/TEMP are intentionally preserved.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE CREATE ON DATABASE %I FROM %I, %I, %I',
        pg_catalog.current_database(),
        'utop14_app',
        'utop14_retention_owner',
        'utop14_retention_runner'
    );
    EXECUTE pg_catalog.format(
        'REVOKE CREATE ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END $$;

-- ---------------------------------------------------------------------------
-- 2. Default-deny membership reconciliation
--
-- The allowlist is intentionally empty.  Add "member:granted_role" entries
-- here and in the verification script only after a documented review.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_allowed text[] := ARRAY[]::text[];
    r record;
BEGIN
    FOR r IN
        SELECT u.rolname AS member_role, g.rolname AS granted_role
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles u ON u.oid = m.member
        JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
        WHERE u.rolname IN ('utop14_app',
                            'utop14_retention_owner',
                            'utop14_retention_runner')
    LOOP
        IF r.member_role || ':' || r.granted_role = ANY (v_allowed) THEN
            RAISE NOTICE 'KEEP allowed membership: % -> %',
                r.member_role, r.granted_role;
        ELSE
            EXECUTE pg_catalog.format('REVOKE %I FROM %I',
                           r.granted_role, r.member_role);
            RAISE NOTICE 'REVOKED forbidden membership: % -> % (default-deny)',
                r.member_role, r.granted_role;
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Schema access: usage only, never CREATE, and only on public
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public
    TO utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE CREATE ON SCHEMA public
    FROM utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 4. Application role: reset then grant the complete least-privilege matrix.
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

-- No function EXECUTE for the app, including trigger/helper functions.
-- PostgreSQL checks trigger-function EXECUTE when the trigger is created, not
-- when it fires, so APP INSERT/UPDATE on security_event_retention_holds still
-- works without this grant.  The app therefore gets no direct trigger-function
-- privilege.

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
-- 5. Retention owner: reset then grant only the retention boundary.
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

-- Trigger/helper functions are trigger-only and not SECURITY DEFINER.  PUBLIC
-- must not execute them directly, and neither the app nor the retention roles
-- receive EXECUTE.  The schema owner keeps only its owner privileges.
REVOKE ALL ON FUNCTION public.security_event_retention_holds_lock()
    FROM PUBLIC, utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE ALL ON FUNCTION public.audit_logs_reject_mutation()
    FROM PUBLIC, utop14_app, utop14_retention_owner, utop14_retention_runner;
REVOKE ALL ON FUNCTION public.security_events_reject_mutation()
    FROM PUBLIC, utop14_app, utop14_retention_owner, utop14_retention_runner;

-- Explicitly keep dangerous privileges away from the retention roles.
REVOKE UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_owner;
REVOKE UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_runner;
REVOKE DELETE, UPDATE, TRUNCATE ON public.security_events FROM utop14_retention_runner;
REVOKE TRUNCATE, TRIGGER, REFERENCES ON ALL TABLES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;
REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA public
    FROM utop14_retention_owner, utop14_retention_runner;

-- ---------------------------------------------------------------------------
-- 6. Postconditions: fail the transaction if reconciliation did not hold.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_membership text;
BEGIN
    -- Forward memberships must all be gone.
    SELECT pg_catalog.format('%s -> %s', u.rolname, g.rolname) INTO v_membership
    FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles u ON u.oid = m.member
    JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
    WHERE u.rolname IN ('utop14_app',
                        'utop14_retention_owner',
                        'utop14_retention_runner')
    LIMIT 1;
    IF v_membership IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: postcondition membership still present: %',
            v_membership;
    END IF;

    IF pg_catalog.has_function_privilege(
        'utop14_app',
        'public.security_event_retention_holds_lock()',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition app still has hold-lock trigger EXECUTE';
    END IF;
    IF pg_catalog.has_function_privilege(
        'utop14_app',
        'public.prune_security_events(text, timestamptz, integer, uuid, integer)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition app has retention function EXECUTE';
    END IF;
    IF pg_catalog.has_schema_privilege('utop14_app', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: postcondition app has schema CREATE';
    END IF;
    IF pg_catalog.has_database_privilege('utop14_app', pg_catalog.current_database(), 'CREATE')
       OR pg_catalog.has_database_privilege('utop14_retention_owner',
                                 pg_catalog.current_database(), 'CREATE')
       OR pg_catalog.has_database_privilege('utop14_retention_runner',
                                 pg_catalog.current_database(), 'CREATE') THEN
        RAISE EXCEPTION
            'FAIL: postcondition managed role still has database CREATE';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database d
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(d.datacl, pg_catalog.acldefault('d', d.datdba))
        ) a
        WHERE d.datname = pg_catalog.current_database()
          AND a.grantee = 0
          AND a.privilege_type = 'CREATE'
    ) THEN
        RAISE EXCEPTION 'FAIL: postcondition PUBLIC has database CREATE';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_app'
          AND rolconfig IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM pg_catalog.unnest(rolconfig) c
              WHERE pg_catalog.replace(pg_catalog.replace(c, ' ', ''), '"', '')
                    = 'search_path=public,pg_catalog'
          )
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition app search_path is not public, pg_catalog';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_db_role_setting s
        CROSS JOIN LATERAL pg_catalog.unnest(s.setconfig) c
        WHERE s.setrole = 'utop14_app'::regrole
          AND s.setdatabase = (
              SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database()
          )
          AND pg_catalog.replace(pg_catalog.replace(c, ' ', ''), '"', '') LIKE 'search_path=%'
          AND pg_catalog.replace(pg_catalog.replace(c, ' ', ''), '"', '')
                <> 'search_path=public,pg_catalog'
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition app has an overriding database-level search_path';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND a.attacl IS NOT NULL
          AND x.grantee <> c.relowner
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition unexpected non-owner column ACL remains';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f', 'S')
          AND pg_catalog.pg_get_userbyid(c.relowner) IN ('utop14_app',
                                              'utop14_retention_owner',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: postcondition app/retention role owns an object';
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 6b. Postconditions: parameter ACLs and persistent GUC configuration
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_entry text;
    v_app_entries integer;
    v_schema_super boolean;
    v_app_oid oid := 'utop14_app'::regrole;
    v_owner_oid oid := 'utop14_retention_owner'::regrole;
    v_runner_oid oid := 'utop14_retention_runner'::regrole;
    v_schema_oid oid := 'utop14_schema_owner'::regrole;
    v_sensitive text[] := ARRAY[
        'shared_preload_libraries',
        'session_preload_libraries',
        'local_preload_libraries',
        'log_statement',
        'log_min_duration_statement',
        'log_min_error_statement',
        'log_min_messages',
        'log_destination',
        'logging_collector',
        'log_connections',
        'log_disconnections',
        'log_duration',
        'log_hostname',
        'log_line_prefix',
        'log_statement_sample_rate',
        'log_transaction_sample_rate',
        'search_path'
    ];
BEGIN
    SELECT coalesce(pg_catalog.array_length(rolconfig, 1), 0)
      INTO v_app_entries
      FROM pg_catalog.pg_roles
     WHERE rolname = 'utop14_app';
    IF v_app_entries IS NULL OR v_app_entries <> 1
       OR NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_roles,
                LATERAL pg_catalog.unnest(rolconfig) c
           WHERE rolname = 'utop14_app'
             AND pg_catalog.replace(pg_catalog.replace(c, ' ', ''), '"', '')
                   = 'search_path=public,pg_catalog'
       ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition app role-level settings are not exactly search_path=public, pg_catalog';
    END IF;

    SELECT rolsuper INTO v_schema_super
    FROM pg_catalog.pg_roles
    WHERE rolname = 'utop14_schema_owner';

    FOR r IN
        SELECT rolname, rolconfig
        FROM pg_catalog.pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner')
    LOOP
        IF r.rolconfig IS NOT NULL
           AND pg_catalog.array_length(r.rolconfig, 1) > 0 THEN
            RAISE EXCEPTION
                'FAIL: postcondition % still has role-level GUC %',
                r.rolname, r.rolconfig;
        END IF;
    END LOOP;

    FOR r IN
        SELECT rolconfig
        FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_schema_owner'
    LOOP
        IF r.rolconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.rolconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: postcondition schema owner unapproved role-level GUC %',
                        v_entry;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    FOR r IN
        SELECT pg_catalog.pg_get_userbyid(s.setrole) AS role_name,
               coalesce(
                   d.datname,
                   pg_catalog.format('UNKNOWN DATABASE (oid=%s)', s.setdatabase)
               ) AS dbname,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole IN (v_app_oid, v_owner_oid, v_runner_oid)
          AND s.setdatabase <> 0
    LOOP
        IF r.setconfig IS NOT NULL
           AND pg_catalog.array_length(r.setconfig, 1) > 0 THEN
            RAISE EXCEPTION
                'FAIL: postcondition % has database-specific GUC % in database %',
                r.role_name, r.setconfig, r.dbname;
        END IF;
    END LOOP;

    FOR r IN
        SELECT coalesce(
                   d.datname,
                   pg_catalog.format('UNKNOWN DATABASE (oid=%s)', s.setdatabase)
               ) AS dbname,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole = v_schema_oid
          AND s.setdatabase <> 0
    LOOP
        IF r.setconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.setconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: postcondition schema owner unapproved database-specific GUC % in %',
                        v_entry, r.dbname;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    FOR r IN
        SELECT coalesce(d.datname, 'ALL DATABASES') AS dbname,
               s.setdatabase,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole = 0
    LOOP
        IF r.setconfig IS NOT NULL
           AND pg_catalog.array_length(r.setconfig, 1) > 0 THEN
            RAISE EXCEPTION
                'FAIL: postcondition database-wide GUC % in % (setdatabase=%) remains',
                r.setconfig, r.dbname, r.setdatabase;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_parameter_acl p
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.paracl) a
        WHERE a.grantee = 0
           OR a.grantee IN (v_app_oid, v_owner_oid,
                            v_runner_oid, v_schema_oid)
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition managed-role/PUBLIC parameter privilege remains';
    END IF;

    FOR r IN SELECT parname FROM pg_catalog.pg_parameter_acl LOOP
        IF pg_catalog.has_parameter_privilege(
            'utop14_app', r.parname, 'SET'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_app', r.parname, 'ALTER SYSTEM'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_retention_owner', r.parname, 'SET'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_retention_owner', r.parname, 'ALTER SYSTEM'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_retention_runner', r.parname, 'SET'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_retention_runner', r.parname, 'ALTER SYSTEM'
        ) THEN
            RAISE EXCEPTION
                'FAIL: postcondition effective parameter privilege remains on %',
                r.parname;
        END IF;
        IF NOT v_schema_super
           AND (pg_catalog.has_parameter_privilege(
                    'utop14_schema_owner', r.parname, 'SET'
                ) OR pg_catalog.has_parameter_privilege(
                    'utop14_schema_owner', r.parname, 'ALTER SYSTEM'
                )) THEN
            RAISE EXCEPTION
                'FAIL: postcondition schema-owner parameter privilege remains on %',
                r.parname;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile IS NOT NULL
          AND sourcefile LIKE '%postgresql.auto.conf'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_file_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile LIKE '%postgresql.auto.conf'
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition sensitive GUC remains in postgresql.auto.conf; DBA reconciliation required';
    END IF;
END $$;

COMMIT;

\echo 'ROLE PROVISIONING COMMITTED SUCCESSFULLY'
