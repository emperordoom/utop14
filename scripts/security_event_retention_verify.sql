-- UTOP14 security-event retention privilege verification (M14.3.3.2).
--
-- Run as the DBA/schema owner (NOT as utop14_app) after migrations and role
-- provisioning.  The script is read-only except for privilege probes that are
-- rolled back if they unexpectedly succeed.  It exits non-zero on the first
-- failed required assertion (psql ON_ERROR_STOP).
--
-- Replace utop14_app and public with the deployment application login role and
-- schema if they differ.  Every assertion names its role explicitly; do not
-- assume a result for one role applies to another.

\set ON_ERROR_STOP on
\pset pager off

-- ---------------------------------------------------------------------------
-- Role attributes and LOGIN/NOLOGIN
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner',
                          'utop14_app')
          AND (rolsuper OR rolcreatedb OR rolcreaterole
               OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role has SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'utop14_retention_owner' AND NOT rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_retention_owner must exist and be NOLOGIN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'utop14_retention_runner' AND rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_retention_runner must exist and be LOGIN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'utop14_app' AND rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app must exist and be LOGIN';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner')
          AND rolinherit
    ) THEN
        RAISE EXCEPTION 'FAIL: retention roles must be NOINHERIT';
    END IF;
    RAISE NOTICE 'PASS: role attributes, LOGIN/NOLOGIN, NOINHERIT';
END $$;

-- ---------------------------------------------------------------------------
-- Memberships: no one in retention roles; retention roles in nothing;
-- app cannot reach owner via direct or transitive membership.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE roleid IN ('utop14_retention_owner'::regrole,
                         'utop14_retention_runner'::regrole)
    ) THEN
        RAISE EXCEPTION 'FAIL: a role is a member of a retention role';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
        WHERE member IN ('utop14_retention_owner'::regrole,
                         'utop14_retention_runner'::regrole)
    ) THEN
        RAISE EXCEPTION 'FAIL: a retention role is a member of another role';
    END IF;
    IF pg_has_role('utop14_app', 'utop14_retention_owner', 'member')
       OR pg_has_role('utop14_app', 'utop14_retention_runner', 'member')
       OR pg_has_role('utop14_retention_runner', 'utop14_retention_owner', 'member') THEN
        RAISE EXCEPTION 'FAIL: forbidden direct/transitive retention membership';
    END IF;

    -- The app must not be able to become any role that owns a security or
    -- retention object.  Check both inherited USAGE and SET-only membership,
    -- which pg_has_role(..., 'SET') resolves through transitive membership.
    FOR r IN
        SELECT DISTINCT owner::text AS owner_role
        FROM (
            SELECT pg_get_userbyid(datdba)::text AS owner
            FROM pg_database
            WHERE datname = current_database()
            UNION
            SELECT nspowner::regrole::text
            FROM pg_namespace
            WHERE nspname = 'public'
            UNION
            SELECT tableowner::text
            FROM pg_tables
            WHERE schemaname = 'public'
              AND tablename IN ('security_events',
                                'security_event_retention_holds',
                                'security_event_retention_runs')
            UNION
            SELECT pg_get_userbyid(c.relowner)::text
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind = 'S'
              AND c.relname IN ('security_events_id_seq',
                                'security_event_retention_holds_id_seq',
                                'security_event_retention_runs_id_seq')
            UNION
            SELECT pg_get_userbyid(p.proowner)::text
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname IN ('prune_security_events',
                                'security_event_retention_holds_lock',
                                'security_events_reject_mutation')
        ) owners
    LOOP
        CONTINUE WHEN r.owner_role IS NULL OR r.owner_role = 'utop14_app';
        IF pg_has_role('utop14_app'::name, r.owner_role::name, 'SET'::text)
           OR pg_has_role('utop14_app'::name, r.owner_role::name, 'USAGE'::text) THEN
            RAISE EXCEPTION
                'FAIL: utop14_app can assume owner role % (SET/USAGE membership)',
                r.owner_role;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_auth_members m
            WHERE m.member = 'utop14_app'::regrole
              AND m.roleid = r.owner_role::regrole
        ) THEN
            RAISE EXCEPTION
                'FAIL: utop14_app has direct membership in owner role %',
                r.owner_role;
        END IF;
    END LOOP;

    FOR r IN
        SELECT roleid::regrole::text AS granted_role
        FROM pg_auth_members
        WHERE member = 'utop14_app'::regrole
    LOOP
        RAISE NOTICE 'INFO: utop14_app is a member of %; review whether required',
            r.granted_role;
    END LOOP;
    RAISE NOTICE 'PASS: membership and SET ROLE paths';
END $$;

-- ---------------------------------------------------------------------------
-- Schema USAGE / CREATE
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT has_schema_privilege('utop14_retention_owner', 'public', 'USAGE')
       OR NOT has_schema_privilege('utop14_retention_runner', 'public', 'USAGE')
       OR NOT has_schema_privilege('utop14_app', 'public', 'USAGE') THEN
        RAISE EXCEPTION 'FAIL: app/retention role lacks schema USAGE';
    END IF;
    IF has_schema_privilege('utop14_retention_owner', 'public', 'CREATE')
       OR has_schema_privilege('utop14_retention_runner', 'public', 'CREATE')
       OR has_schema_privilege('utop14_app', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: app/retention role has schema CREATE';
    END IF;
    RAISE NOTICE 'PASS: schema USAGE present, CREATE absent';
END $$;

-- ---------------------------------------------------------------------------
-- Ownership separation (OPS-01)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_owner text;
BEGIN
    SELECT pg_get_userbyid(datdba) INTO v_owner
    FROM pg_database WHERE datname = current_database();
    IF v_owner = 'utop14_app' THEN
        RAISE EXCEPTION 'FAIL: utop14_app owns the database';
    END IF;

    SELECT nspowner::regrole::text INTO v_owner
    FROM pg_namespace WHERE nspname = 'public';
    IF v_owner = 'utop14_app' THEN
        RAISE EXCEPTION 'FAIL: utop14_app owns schema public';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('security_events',
                            'security_event_retention_holds',
                            'security_event_retention_runs')
          AND tableowner IN ('utop14_app',
                             'utop14_retention_owner',
                             'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role owns a security/retention table';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'S'
          AND c.relname IN ('security_events_id_seq',
                            'security_event_retention_holds_id_seq',
                            'security_event_retention_runs_id_seq')
          AND pg_get_userbyid(c.relowner) IN ('utop14_app',
                                              'utop14_retention_owner',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role owns a retention sequence';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname IN ('prune_security_events',
                            'security_event_retention_holds_lock',
                            'security_events_reject_mutation')
          AND pg_get_userbyid(p.proowner) = 'utop14_app'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app owns a retention/trigger function';
    END IF;

    -- The trigger/helper functions belong to the DDL/schema owner, not to a
    -- retention role.  prune_security_events is intentionally excluded: it
    -- must stay owned by utop14_retention_owner.
    IF EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname IN ('security_event_retention_holds_lock',
                            'security_events_reject_mutation')
          AND pg_get_userbyid(p.proowner) IN ('utop14_retention_owner',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: a retention role owns a trigger/helper function';
    END IF;

    RAISE NOTICE 'PASS: app is not database/schema/table/sequence/function owner';
END $$;

-- ---------------------------------------------------------------------------
-- security_events privilege matrix
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF has_table_privilege('utop14_app', 'security_events', 'DELETE')
       OR has_table_privilege('utop14_app', 'security_events', 'UPDATE')
       OR has_table_privilege('utop14_app', 'security_events', 'TRUNCATE')
       OR has_table_privilege('utop14_app', 'security_events', 'TRIGGER')
       OR has_table_privilege('utop14_app', 'security_events', 'REFERENCES') THEN
        RAISE EXCEPTION 'FAIL: app has dangerous security_events privileges';
    END IF;
    IF NOT has_table_privilege('utop14_app', 'security_events', 'SELECT')
       OR NOT has_table_privilege('utop14_app', 'security_events', 'INSERT') THEN
        RAISE EXCEPTION 'FAIL: app lacks required security_events SELECT/INSERT';
    END IF;

    IF has_table_privilege('utop14_retention_runner', 'security_events', 'SELECT')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'INSERT')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'DELETE')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'UPDATE')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'TRUNCATE')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'TRIGGER')
       OR has_table_privilege('utop14_retention_runner', 'security_events', 'REFERENCES') THEN
        RAISE EXCEPTION 'FAIL: runner has direct security_events privileges';
    END IF;

    IF NOT has_table_privilege('utop14_retention_owner', 'security_events', 'SELECT')
       OR NOT has_table_privilege('utop14_retention_owner', 'security_events', 'DELETE') THEN
        RAISE EXCEPTION 'FAIL: retention owner lacks required security_events SELECT/DELETE';
    END IF;
    IF has_table_privilege('utop14_retention_owner', 'security_events', 'UPDATE')
       OR has_table_privilege('utop14_retention_owner', 'security_events', 'TRUNCATE')
       OR has_table_privilege('utop14_retention_owner', 'security_events', 'TRIGGER')
       OR has_table_privilege('utop14_retention_owner', 'security_events', 'REFERENCES') THEN
        RAISE EXCEPTION 'FAIL: retention owner has dangerous security_events privileges';
    END IF;
    RAISE NOTICE 'PASS: security_events privilege matrix';
END $$;

-- ---------------------------------------------------------------------------
-- Sequence privileges for the M14.1 event writer and hold inserts
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_owner text;
BEGIN
    IF NOT has_sequence_privilege('utop14_app', 'security_events_id_seq', 'USAGE') THEN
        RAISE EXCEPTION 'FAIL: utop14_app lacks USAGE on security_events_id_seq';
    END IF;
    IF NOT has_sequence_privilege('utop14_app', 'security_events_id_seq', 'SELECT') THEN
        RAISE EXCEPTION 'FAIL: utop14_app lacks SELECT on security_events_id_seq';
    END IF;
    IF has_sequence_privilege('utop14_app', 'security_events_id_seq', 'UPDATE') THEN
        RAISE EXCEPTION 'FAIL: utop14_app has UPDATE on security_events_id_seq';
    END IF;

    SELECT pg_get_userbyid(c.relowner) INTO v_owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind = 'S'
      AND c.relname = 'security_events_id_seq';
    IF v_owner = 'utop14_app' THEN
        RAISE EXCEPTION 'FAIL: utop14_app owns security_events_id_seq';
    END IF;

    IF NOT has_sequence_privilege(
        'utop14_app', 'security_event_retention_holds_id_seq', 'USAGE'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app lacks USAGE on the hold sequence';
    END IF;
    IF has_sequence_privilege(
        'utop14_app', 'security_event_retention_holds_id_seq', 'UPDATE'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app has UPDATE on the hold sequence';
    END IF;

    -- Only the retention owner/runner write run rows.
    IF has_sequence_privilege(
        'utop14_app', 'security_event_retention_runs_id_seq', 'USAGE'
    ) OR has_sequence_privilege(
        'utop14_app', 'security_event_retention_runs_id_seq', 'SELECT'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app has unnecessary run-log sequence privileges';
    END IF;
    RAISE NOTICE 'PASS: app sequence privileges and non-ownership';
END $$;

-- ---------------------------------------------------------------------------
-- Holds and run-log privilege matrix
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT has_table_privilege('utop14_app', 'security_event_retention_holds', 'SELECT')
       OR NOT has_table_privilege('utop14_app', 'security_event_retention_holds', 'INSERT')
       OR NOT has_table_privilege('utop14_app', 'security_event_retention_holds', 'UPDATE') THEN
        RAISE EXCEPTION 'FAIL: app lacks required hold SELECT/INSERT/UPDATE';
    END IF;
    IF has_table_privilege('utop14_app', 'security_event_retention_holds', 'DELETE')
       OR has_table_privilege('utop14_app', 'security_event_retention_holds', 'TRUNCATE') THEN
        RAISE EXCEPTION 'FAIL: app has hold DELETE/TRUNCATE';
    END IF;

    IF NOT has_table_privilege('utop14_retention_owner', 'security_event_retention_holds', 'SELECT') THEN
        RAISE EXCEPTION 'FAIL: retention owner lacks hold SELECT';
    END IF;
    IF has_table_privilege('utop14_retention_owner', 'security_event_retention_holds', 'UPDATE')
       OR has_table_privilege('utop14_retention_owner', 'security_event_retention_holds', 'DELETE') THEN
        RAISE EXCEPTION 'FAIL: retention owner has hold UPDATE/DELETE';
    END IF;

    IF NOT has_table_privilege('utop14_retention_runner', 'security_event_retention_runs', 'SELECT')
       OR NOT has_table_privilege('utop14_retention_runner', 'security_event_retention_runs', 'INSERT') THEN
        RAISE EXCEPTION 'FAIL: runner lacks run-log SELECT/INSERT';
    END IF;
    IF has_table_privilege('utop14_retention_runner', 'security_event_retention_runs', 'UPDATE')
       OR has_table_privilege('utop14_retention_runner', 'security_event_retention_runs', 'DELETE')
       OR has_table_privilege('utop14_retention_runner', 'security_event_retention_runs', 'TRUNCATE') THEN
        RAISE EXCEPTION 'FAIL: runner can modify run-log history';
    END IF;
    RAISE NOTICE 'PASS: hold and run-log privilege matrix';
END $$;

-- ---------------------------------------------------------------------------
-- Function ownership, SECURITY DEFINER, search_path and EXECUTE
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_owner text;
    v_secdef boolean;
    v_config text[];
BEGIN
    SELECT pg_get_userbyid(p.proowner), p.prosecdef, p.proconfig
      INTO v_owner, v_secdef, v_config
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
       AND p.proname = 'prune_security_events'
       AND p.pronargs = 5;

    IF v_owner IS DISTINCT FROM 'utop14_retention_owner' THEN
        RAISE EXCEPTION 'FAIL: prune_security_events owner=% (expected utop14_retention_owner)', v_owner;
    END IF;
    IF v_secdef IS NOT TRUE THEN
        RAISE EXCEPTION 'FAIL: prune_security_events is not SECURITY DEFINER';
    END IF;
    IF v_config IS NULL
       OR NOT EXISTS (SELECT 1 FROM unnest(v_config) c WHERE c LIKE 'search_path=%') THEN
        RAISE EXCEPTION 'FAIL: prune_security_events search_path is not locked';
    END IF;
    IF NOT has_function_privilege(
        'utop14_retention_runner',
        'public.prune_security_events(text, timestamptz, integer, uuid, integer)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: runner lacks prune_security_events EXECUTE';
    END IF;
    IF has_function_privilege(
        'utop14_app',
        'public.prune_security_events(text, timestamptz, integer, uuid, integer)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: app has prune_security_events EXECUTE';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_proc p,
             aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.oid = 'public.prune_security_events(text, timestamptz, integer, uuid, integer)'::regprocedure
          AND a.grantee = 0
          AND a.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: PUBLIC has prune_security_events EXECUTE';
    END IF;
    RAISE NOTICE 'PASS: function owner, SECURITY DEFINER, search_path, EXECUTE';
END $$;

-- ---------------------------------------------------------------------------
-- App cannot ALTER TABLE or DISABLE TRIGGER (OPS-01)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    EXECUTE 'SET LOCAL ROLE utop14_app';
    BEGIN
        ALTER TABLE public.security_events
            DISABLE TRIGGER security_events_append_only;
        RAISE EXCEPTION 'FAIL: utop14_app can disable the append-only trigger';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS: utop14_app cannot disable the append-only trigger';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    EXECUTE 'SET LOCAL ROLE utop14_app';
    BEGIN
        ALTER TABLE public.security_events ADD COLUMN verify_probe integer;
        RAISE EXCEPTION 'FAIL: utop14_app can ALTER TABLE security_events';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS: utop14_app cannot ALTER TABLE security_events';
    END;
    RESET ROLE;
END $$;

-- ---------------------------------------------------------------------------
-- Dangerous default privileges
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
        FROM pg_default_acl d,
             aclexplode(d.defaclacl) a
        WHERE (d.defaclrole IN ('utop14_app'::regrole,
                                'utop14_retention_owner'::regrole,
                                'utop14_retention_runner'::regrole)
               OR a.grantee IN ('utop14_app'::regrole,
                                'utop14_retention_owner'::regrole,
                                'utop14_retention_runner'::regrole)
               OR a.grantee = 0)
          AND a.privilege_type IN ('DELETE', 'UPDATE', 'TRUNCATE', 'EXECUTE')
    LOOP
        RAISE EXCEPTION
            'FAIL: dangerous default privilege % on % grants to %',
            r.privilege_type, r.owner_role, r.grantee;
    END LOOP;
    RAISE NOTICE 'PASS: no dangerous default privileges for app/retention roles';
END $$;

DO $$
BEGIN
    RAISE NOTICE 'ALL REQUIRED RETENTION PRIVILEGE CHECKS PASSED';
END $$;
