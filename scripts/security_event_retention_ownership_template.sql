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
-- Prerequisites:
--   * utop14_app already exists (it is not created here);
--   * all Alembic migrations have run and the current head is the reviewed
--     head documented in README.md;
--   * the expected object inventory below matches the migrations.
--
-- Safe execution order for a new or existing installation:
--   1. Run all Alembic migrations as <schema_owner>/DBA.
--   2. Run this ownership template as a superuser (review first).
--   3. Run scripts/security_event_retention_roles.sql as a superuser.
--   4. Run scripts/security_event_retention_verify.sql as a PostgreSQL
--      superuser; it must exit 0.
--
-- The template is repeatable: it fails closed before changing anything if the
-- object inventory has drifted, and it is wrapped in a single transaction.
-- Supported PostgreSQL: 16 or newer (membership checks live in the provisioning
-- and verification scripts; this template only needs transactional DDL).
--
-- Do not run this against production without change approval and a backup.

\set ON_ERROR_STOP on
\pset pager off

-- Resolve every unqualified name against pg_catalog first.  A caller-supplied
-- PGOPTIONS or role-level search_path cannot override this session setting, so
-- security-sensitive object and function resolution is deterministic.
SET search_path = pg_catalog, public;

BEGIN;

-- ---------------------------------------------------------------------------
-- Preflight: exact object inventory, no unexpected schemas/types/extensions.
-- This prevents a newly added migration object from being silently ignored by
-- a stale ownership list.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    expected_schemas text[] := ARRAY['public'];
    expected_extensions text[] := ARRAY['plpgsql'];
    expected_tables text[] := ARRAY[
        'admin_security_event_filter_states', 'alembic_version', 'audit_logs',
        'auth_rate_limits', 'cart_items', 'carts', 'categories',
        'order_items', 'orders', 'payment_proofs', 'payments',
        'product_images', 'product_reviews', 'product_variants', 'products',
        'security_event_retention_holds', 'security_event_retention_runs',
        'security_events', 'users'
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
        'public.abandon_retention_run(uuid, integer, text)',
        'public.audit_logs_reject_mutation()',
        'public.begin_retention_run(text, timestamptz, uuid, integer)',
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
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '<schema_owner>') THEN
        RAISE EXCEPTION 'FAIL: schema owner <schema_owner> does not exist';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_app') THEN
        RAISE EXCEPTION 'FAIL: utop14_app does not exist; create the application login role first';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'plpgsql') THEN
        RAISE EXCEPTION 'FAIL: required extension plpgsql is missing';
    END IF;
    SELECT pg_catalog.array_agg(extname ORDER BY extname) INTO v_extra
    FROM pg_catalog.pg_extension WHERE NOT (extname = ANY (expected_extensions));
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried extensions %; review them and update this template',
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
            'FAIL: uninventoried non-system schemas %; review them and update this template',
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
            'FAIL: uninventoried user-defined types/domains %; update this template',
            v_extra;
    END IF;

    SELECT pg_catalog.array_agg(t) INTO v_extra
    FROM pg_catalog.unnest(expected_tables) t
    WHERE pg_catalog.to_regclass(pg_catalog.format('public.%I', t)) IS NULL;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected tables %', v_extra;
    END IF;
    SELECT pg_catalog.array_agg(c.relname ORDER BY c.relname) INTO v_extra
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p', 'f')
      AND NOT (c.relname = ANY (expected_tables))
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
      );
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried tables %', v_extra;
    END IF;

    SELECT pg_catalog.array_agg(s) INTO v_extra
    FROM pg_catalog.unnest(expected_sequences) s
    WHERE pg_catalog.to_regclass(pg_catalog.format('public.%I', s)) IS NULL;
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected sequences %', v_extra;
    END IF;
    SELECT pg_catalog.array_agg(c.relname ORDER BY c.relname) INTO v_extra
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind = 'S'
      AND NOT (c.relname = ANY (expected_sequences))
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
      );
    IF v_extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried sequences %', v_extra;
    END IF;

    FOREACH fn IN ARRAY expected_functions LOOP
        IF pg_catalog.to_regprocedure(fn) IS NULL THEN
            RAISE EXCEPTION 'FAIL: required function % is missing', fn;
        END IF;
    END LOOP;
    SELECT pg_catalog.array_agg(p.proname ORDER BY p.proname) INTO v_extra
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT (p.proname = ANY (ARRAY[
          'abandon_retention_run', 'audit_logs_reject_mutation',
          'begin_retention_run', 'prune_security_events',
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
        RAISE EXCEPTION 'FAIL: unexpected view/materialized view; update this template';
    END IF;

    -- The app must never already own an application object.
    FOR r IN
        SELECT c.relname, pg_catalog.pg_get_userbyid(c.relowner) AS owner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f', 'S')
    LOOP
        IF r.owner = 'utop14_app' THEN
            RAISE EXCEPTION
                'FAIL: utop14_app already owns %; investigate before transferring ownership',
                r.relname;
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- Preflight: parameter ACL support, database-wide/schema-owner GUCs, and
-- sensitive cluster settings in postgresql.auto.conf.  These are DBA-reconciled,
-- never silently reset by this template.
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
            'FAIL: required parameter/GUC catalog support is unavailable; cannot apply this template safely';
    END IF;

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
                'FAIL: database-wide GUC % in % (setdatabase=%) requires DBA reconciliation before applying this template',
                r.setconfig, r.dbname, r.setdatabase;
        END IF;
    END LOOP;

    FOR r IN
        SELECT rolconfig
        FROM pg_catalog.pg_roles
        WHERE rolname = '<schema_owner>'
    LOOP
        IF r.rolconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.rolconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: schema owner has unapproved role-level GUC %; DBA reconciliation required',
                        v_entry;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    FOR r IN
        SELECT coalesce(d.datname, 'UNKNOWN DATABASE') AS dbname,
               s.setconfig
        FROM pg_catalog.pg_db_role_setting s
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
        WHERE s.setrole = '<schema_owner>'::regrole
          AND s.setdatabase <> 0
    LOOP
        IF r.setconfig IS NOT NULL THEN
            FOREACH v_entry IN ARRAY r.setconfig LOOP
                IF pg_catalog.replace(pg_catalog.replace(v_entry, ' ', ''), '"', '')
                   NOT LIKE 'search_path=%' THEN
                    RAISE EXCEPTION
                        'FAIL: schema owner has unapproved database-specific GUC % in %; DBA reconciliation required',
                        v_entry, r.dbname;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    FOR r IN
        SELECT name, setting, sourcefile, pending_restart
        FROM pg_catalog.pg_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile IS NOT NULL
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: sensitive cluster GUC %=% remains in postgresql.auto.conf (%); pending_restart=% requires DBA reconciliation',
            r.name, r.setting, r.sourcefile, r.pending_restart;
    END LOOP;
    FOR r IN
        SELECT sourcefile, name, setting, applied, error
        FROM pg_catalog.pg_file_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: postgresql.auto.conf contains sensitive GUC %=% (%); applied=%, error=% requires DBA reconciliation',
            r.name, r.setting, r.sourcefile, r.applied, r.error;
    END LOOP;
END $$;

-- 1. Database and schema ownership.
ALTER DATABASE <database_name> OWNER TO <schema_owner>;
ALTER SCHEMA public OWNER TO <schema_owner>;

-- 2. Complete application table ownership inventory.
--    Alembic metadata is included so the app cannot own it either.
ALTER TABLE public.alembic_version OWNER TO <schema_owner>;
ALTER TABLE public.admin_security_event_filter_states OWNER TO <schema_owner>;
ALTER TABLE public.users OWNER TO <schema_owner>;
ALTER TABLE public.audit_logs OWNER TO <schema_owner>;
ALTER TABLE public.security_events OWNER TO <schema_owner>;
ALTER TABLE public.auth_rate_limits OWNER TO <schema_owner>;
ALTER TABLE public.security_event_retention_holds OWNER TO <schema_owner>;
ALTER TABLE public.security_event_retention_runs OWNER TO <schema_owner>;
ALTER TABLE public.categories OWNER TO <schema_owner>;
ALTER TABLE public.products OWNER TO <schema_owner>;
ALTER TABLE public.product_variants OWNER TO <schema_owner>;
ALTER TABLE public.product_images OWNER TO <schema_owner>;
ALTER TABLE public.carts OWNER TO <schema_owner>;
ALTER TABLE public.cart_items OWNER TO <schema_owner>;
ALTER TABLE public.orders OWNER TO <schema_owner>;
ALTER TABLE public.order_items OWNER TO <schema_owner>;
ALTER TABLE public.payments OWNER TO <schema_owner>;
ALTER TABLE public.payment_proofs OWNER TO <schema_owner>;
ALTER TABLE public.product_reviews OWNER TO <schema_owner>;

-- 3. Complete sequence ownership inventory.  These are the SERIAL sequences
--    for every application table that has one.  auth_rate_limits uses a
--    composite primary key and has no sequence.
ALTER SEQUENCE public.users_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.audit_logs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.security_events_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.security_event_retention_holds_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.security_event_retention_runs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.categories_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.products_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.product_variants_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.product_images_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.carts_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.cart_items_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.orders_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.order_items_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.payments_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.payment_proofs_id_seq OWNER TO <schema_owner>;
ALTER SEQUENCE public.product_reviews_id_seq OWNER TO <schema_owner>;

-- 4. Trigger/helper functions belong to the DDL/schema owner.  They are not
--    SECURITY DEFINER and hold no elevated privileges.
ALTER FUNCTION public.audit_logs_reject_mutation() OWNER TO <schema_owner>;
ALTER FUNCTION public.security_events_reject_mutation() OWNER TO <schema_owner>;
ALTER FUNCTION public.security_event_retention_holds_lock() OWNER TO <schema_owner>;

-- 5. Do NOT transfer the SECURITY DEFINER retention entry point:
--    public.begin_retention_run, public.abandon_retention_run and
--    public.prune_security_events must stay owned by
--    utop14_retention_owner.  Role provisioning sets this ownership explicitly.

-- 6. Remove schema CREATE from untrusted roles.  USAGE is retained.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM utop14_app;

-- 6b. Remove database-level CREATE from the app, retention roles (if they
--     already exist), and PUBLIC.  CONNECT/TEMP are intentionally preserved.
--     Run this template connected to the application database; current_database()
--     is used for the database privilege revocation.
DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['utop14_app',
                             'utop14_retention_owner',
                             'utop14_retention_runner'] LOOP
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r) THEN
            EXECUTE pg_catalog.format(
                'REVOKE CREATE ON DATABASE %I FROM %I',
                pg_catalog.current_database(), r
            );
        END IF;
    END LOOP;
    EXECUTE pg_catalog.format(
        'REVOKE CREATE ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END $$;

-- 6c. Reset persistent GUCs for the managed roles, then apply the approved app
--     search_path.  Database-wide and schema-owner GUCs are DBA-reconciled by
--     the preflight above and are not modified here.
DO $$
DECLARE
    r text;
    db text;
BEGIN
    FOREACH r IN ARRAY ARRAY['utop14_app',
                             'utop14_retention_owner',
                             'utop14_retention_runner'] LOOP
        IF EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r
        ) THEN
            EXECUTE pg_catalog.format('ALTER ROLE %I RESET ALL', r);
            FOR db IN
                SELECT datname
                FROM pg_catalog.pg_database
                WHERE NOT datistemplate
            LOOP
                EXECUTE pg_catalog.format(
                    'ALTER ROLE %I IN DATABASE %I RESET ALL',
                    r, db
                );
            END LOOP;
        END IF;
    END LOOP;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'utop14_app'
    ) THEN
        EXECUTE 'ALTER ROLE utop14_app SET search_path = public, pg_catalog';
    END IF;
END $$;

-- 6d. Reconcile parameter SET/ALTER SYSTEM grants for managed roles and PUBLIC.
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
           OR pg_catalog.pg_get_userbyid(a.grantee) IN (
               'utop14_app',
               'utop14_retention_owner',
               'utop14_retention_runner',
               'utop14_schema_owner'
           )
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
-- 7. Postconditions: every application object must be owned by the schema
-- owner; the app/retention roles must not own anything.  The retention
-- function may still be owned by the schema owner before first provisioning,
-- or by utop14_retention_owner afterwards.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_owner text;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(datdba) INTO v_owner
    FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database();
    IF v_owner IS DISTINCT FROM '<schema_owner>' THEN
        RAISE EXCEPTION 'FAIL: postcondition database owner=%', v_owner;
    END IF;
    SELECT nspowner::regrole::text INTO v_owner
    FROM pg_catalog.pg_namespace WHERE nspname = 'public';
    IF v_owner IS DISTINCT FROM '<schema_owner>' THEN
        RAISE EXCEPTION 'FAIL: postcondition schema public owner=%', v_owner;
    END IF;

    IF pg_catalog.has_database_privilege('utop14_app', pg_catalog.current_database(), 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: postcondition utop14_app has database CREATE';
    END IF;
    IF pg_catalog.to_regrole('utop14_retention_owner') IS NOT NULL THEN
        IF pg_catalog.has_database_privilege(
            'utop14_retention_owner', pg_catalog.current_database(), 'CREATE'
        ) THEN
            RAISE EXCEPTION
                'FAIL: postcondition utop14_retention_owner has database CREATE';
        END IF;
    END IF;
    IF pg_catalog.to_regrole('utop14_retention_runner') IS NOT NULL THEN
        IF pg_catalog.has_database_privilege(
            'utop14_retention_runner', pg_catalog.current_database(), 'CREATE'
        ) THEN
            RAISE EXCEPTION
                'FAIL: postcondition utop14_retention_runner has database CREATE';
        END IF;
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

    FOR r IN
        SELECT c.relname, pg_catalog.pg_get_userbyid(c.relowner) AS owner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f', 'S')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        IF r.owner IS DISTINCT FROM '<schema_owner>' THEN
            RAISE EXCEPTION 'FAIL: postcondition % owner=%', r.relname, r.owner;
        END IF;
    END LOOP;

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
        IF r.proname IN (
            'abandon_retention_run', 'begin_retention_run', 'prune_security_events'
        ) THEN
            IF r.owner NOT IN ('<schema_owner>', 'utop14_retention_owner') THEN
                RAISE EXCEPTION 'FAIL: postcondition retention function % owner=%',
                    r.proname, r.owner;
            END IF;
        ELSIF r.owner IS DISTINCT FROM '<schema_owner>' THEN
            RAISE EXCEPTION 'FAIL: postcondition helper function % owner=%',
                r.proname, r.owner;
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 7b. Postconditions: persistent GUCs and parameter ACLs
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_entry text;
    v_app_entries integer;
    v_schema_super boolean;
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
    WHERE rolname = '<schema_owner>';

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
        WHERE rolname = '<schema_owner>'
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
        WHERE pg_catalog.pg_get_userbyid(s.setrole) IN (
                  'utop14_app',
                  'utop14_retention_owner',
                  'utop14_retention_runner'
              )
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
        WHERE s.setrole = '<schema_owner>'::regrole
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
           OR pg_catalog.pg_get_userbyid(a.grantee) IN (
                  'utop14_app',
                  'utop14_retention_owner',
                  'utop14_retention_runner',
                  '<schema_owner>'
              )
    ) THEN
        RAISE EXCEPTION
            'FAIL: postcondition managed-role/PUBLIC parameter privilege remains';
    END IF;

    FOR r IN SELECT parname FROM pg_catalog.pg_parameter_acl LOOP
        IF pg_catalog.has_parameter_privilege(
            'utop14_app', r.parname, 'SET'
        ) OR pg_catalog.has_parameter_privilege(
            'utop14_app', r.parname, 'ALTER SYSTEM'
        ) THEN
            RAISE EXCEPTION
                'FAIL: postcondition app parameter privilege remains on %',
                r.parname;
        END IF;
        IF pg_catalog.to_regrole('utop14_retention_owner') IS NOT NULL THEN
            IF pg_catalog.has_parameter_privilege(
                'utop14_retention_owner', r.parname, 'SET'
            ) OR pg_catalog.has_parameter_privilege(
                'utop14_retention_owner', r.parname, 'ALTER SYSTEM'
            ) THEN
                RAISE EXCEPTION
                    'FAIL: postcondition retention-owner parameter privilege remains on %',
                    r.parname;
            END IF;
        END IF;
        IF pg_catalog.to_regrole('utop14_retention_runner') IS NOT NULL THEN
            IF pg_catalog.has_parameter_privilege(
                'utop14_retention_runner', r.parname, 'SET'
            ) OR pg_catalog.has_parameter_privilege(
                'utop14_retention_runner', r.parname, 'ALTER SYSTEM'
            ) THEN
                RAISE EXCEPTION
                    'FAIL: postcondition retention-runner parameter privilege remains on %',
                    r.parname;
            END IF;
        END IF;
        IF NOT v_schema_super
           AND (pg_catalog.has_parameter_privilege(
                    '<schema_owner>', r.parname, 'SET'
                ) OR pg_catalog.has_parameter_privilege(
                    '<schema_owner>', r.parname, 'ALTER SYSTEM'
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

-- 8. Verify the intended model.  This script must exit 0.
--    \i scripts/security_event_retention_verify.sql
