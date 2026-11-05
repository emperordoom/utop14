-- UTOP14 comprehensive application and retention privilege verification.
--
-- Run as the DBA/schema owner (NOT as utop14_app) after:
--   migrations -> ownership template -> role provisioning.
-- The script is read-only except for privilege probes that are rolled back if
-- they unexpectedly succeed.  It exits non-zero on the first failed assertion.
--
-- Replace utop14_app / utop14_schema_owner / public with deployment values if
-- they differ.  Every assertion names its role explicitly.

\set ON_ERROR_STOP on
\pset pager off

-- ---------------------------------------------------------------------------
-- 1. Role attributes and LOGIN/NOLOGIN
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- The dedicated DDL/schema owner may be a DBA (possibly privileged); the
    -- app and retention roles must not be.  The ownership/membership checks
    -- below still prove the schema owner is separate from those roles.
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner',
                          'utop14_app')
          AND (rolsuper OR rolcreatedb OR rolcreaterole
               OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'FAIL: application/retention role has SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = 'utop14_schema_owner'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_schema_owner is missing';
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
    RAISE NOTICE 'PASS: role attributes and LOGIN/NOLOGIN';
END $$;

-- ---------------------------------------------------------------------------
-- 2. Complete object inventory (fail on missing or uninventoried objects)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
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
        'audit_logs_reject_mutation', 'prune_security_events',
        'security_event_retention_holds_lock', 'security_events_reject_mutation'
    ];
    expected_triggers text[] := ARRAY[
        'audit_logs_append_only', 'security_event_retention_holds_lock',
        'security_events_append_only'
    ];
    missing text[];
    extra text[];
    fn text;
BEGIN
    SELECT array_agg(t) INTO missing
    FROM unnest(expected_tables) t
    WHERE to_regclass(format('public.%I', t)) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected tables %', missing;
    END IF;
    SELECT array_agg(tablename) INTO extra
    FROM pg_tables
    WHERE schemaname = 'public'
      AND NOT (tablename = ANY (expected_tables));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried tables %', extra;
    END IF;

    SELECT array_agg(s) INTO missing
    FROM unnest(expected_sequences) s
    WHERE to_regclass(format('public.%I', s)) IS NULL;
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected sequences %', missing;
    END IF;
    SELECT array_agg(sequencename) INTO extra
    FROM pg_sequences
    WHERE schemaname = 'public'
      AND NOT (sequencename = ANY (expected_sequences));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried sequences %', extra;
    END IF;

    FOREACH fn IN ARRAY expected_functions LOOP
        IF (SELECT count(*) FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = fn) <> 1 THEN
            RAISE EXCEPTION 'FAIL: expected exactly one function named %', fn;
        END IF;
    END LOOP;
    SELECT array_agg(p.proname) INTO extra
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT (p.proname = ANY (expected_functions));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried functions %', extra;
    END IF;

    SELECT array_agg(t) INTO missing
    FROM unnest(expected_triggers) t
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_trigger tr
        JOIN pg_class c ON c.oid = tr.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND tr.tgname = t AND NOT tr.tgisinternal
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected triggers %', missing;
    END IF;
    SELECT array_agg(tr.tgname) INTO extra
    FROM pg_trigger tr
    JOIN pg_class c ON c.oid = tr.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND NOT tr.tgisinternal
      AND NOT (tr.tgname = ANY (expected_triggers));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried triggers %', extra;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_views WHERE schemaname = 'public')
       OR EXISTS (SELECT 1 FROM pg_matviews WHERE schemaname = 'public') THEN
        RAISE EXCEPTION 'FAIL: unexpected view/materialized view; update inventory';
    END IF;

    RAISE NOTICE 'PASS: complete object inventory';
END $$;

-- ---------------------------------------------------------------------------
-- 3. Ownership inventory
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_owner text;
BEGIN
    SELECT pg_get_userbyid(datdba) INTO v_owner
    FROM pg_database WHERE datname = current_database();
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION 'FAIL: database owner=% (expected utop14_schema_owner)', v_owner;
    END IF;

    SELECT nspowner::regrole::text INTO v_owner
    FROM pg_namespace WHERE nspname = 'public';
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION 'FAIL: schema public owner=% (expected utop14_schema_owner)', v_owner;
    END IF;

    FOR r IN
        SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'
    LOOP
        IF r.tableowner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: table % owner=%', r.tablename, r.tableowner;
        END IF;
    END LOOP;

    FOR r IN
        SELECT c.relname, pg_get_userbyid(c.relowner) AS owner
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'S'
    LOOP
        IF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: sequence % owner=%', r.relname, r.owner;
        END IF;
    END LOOP;

    FOR r IN
        SELECT p.proname, pg_get_userbyid(p.proowner) AS owner
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
    LOOP
        IF r.proname = 'prune_security_events' THEN
            IF r.owner IS DISTINCT FROM 'utop14_retention_owner' THEN
                RAISE EXCEPTION 'FAIL: prune_security_events owner=%', r.owner;
            END IF;
        ELSIF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: helper function % owner=%', r.proname, r.owner;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM pg_tables
        WHERE schemaname = 'public'
          AND tableowner IN ('utop14_app',
                             'utop14_retention_owner',
                             'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role owns an application table';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'S'
          AND pg_get_userbyid(c.relowner) IN ('utop14_app',
                                              'utop14_retention_owner',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role owns a sequence';
    END IF;

    RAISE NOTICE 'PASS: ownership inventory';
END $$;

-- ---------------------------------------------------------------------------
-- 4. Membership / SET ROLE escalation paths
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

    -- Collect every database/schema/table/sequence/function owner plus the
    -- retention roles, then prove the app cannot SET/USAGE any of them.
    FOR r IN
        SELECT DISTINCT owner::text AS owner_role
        FROM (
            SELECT pg_get_userbyid(datdba)::text AS owner
            FROM pg_database WHERE datname = current_database()
            UNION
            SELECT nspowner::regrole::text
            FROM pg_namespace WHERE nspname = 'public'
            UNION
            SELECT tableowner::text
            FROM pg_tables WHERE schemaname = 'public'
            UNION
            SELECT pg_get_userbyid(c.relowner)::text
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'S'
            UNION
            SELECT pg_get_userbyid(p.proowner)::text
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
            UNION
            SELECT 'utop14_retention_runner'
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
            SELECT 1 FROM pg_auth_members m
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
-- 5. Schema privileges
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT has_schema_privilege('utop14_app', 'public', 'USAGE')
       OR NOT has_schema_privilege('utop14_retention_owner', 'public', 'USAGE')
       OR NOT has_schema_privilege('utop14_retention_runner', 'public', 'USAGE')
       OR NOT has_schema_privilege('utop14_schema_owner', 'public', 'USAGE') THEN
        RAISE EXCEPTION 'FAIL: application/retention role lacks schema USAGE';
    END IF;
    IF has_schema_privilege('utop14_app', 'public', 'CREATE')
       OR has_schema_privilege('utop14_retention_owner', 'public', 'CREATE')
       OR has_schema_privilege('utop14_retention_runner', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: app/retention role has schema CREATE';
    END IF;
    IF NOT has_schema_privilege('utop14_schema_owner', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: schema owner lacks schema CREATE';
    END IF;
    RAISE NOTICE 'PASS: schema USAGE/CREATE';
END $$;

-- ---------------------------------------------------------------------------
-- 6. Application table privilege matrix
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    p text;
BEGIN
    FOR r IN
        SELECT * FROM (VALUES
            ('alembic_version', ARRAY[]::text[]),
            ('audit_logs', ARRAY['SELECT','INSERT']::text[]),
            ('auth_rate_limits', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[]),
            ('cart_items', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[]),
            ('carts', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('categories', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('order_items', ARRAY['SELECT','INSERT']::text[]),
            ('orders', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('payment_proofs', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('payments', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('product_images', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[]),
            ('product_reviews', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('product_variants', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('products', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('security_event_retention_holds', ARRAY['SELECT','INSERT','UPDATE']::text[]),
            ('security_event_retention_runs', ARRAY[]::text[]),
            ('security_events', ARRAY['SELECT','INSERT']::text[]),
            ('users', ARRAY['SELECT','INSERT','UPDATE']::text[])
        ) AS t(table_name, allowed)
    LOOP
        FOR p IN SELECT unnest(
            ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']::text[]
        )
        LOOP
            IF has_table_privilege('utop14_app', r.table_name, p)
               <> (p = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: app privilege % on % expected=%',
                    p, r.table_name, (p = ANY (r.allowed));
            END IF;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: application table privilege matrix';
END $$;

-- ---------------------------------------------------------------------------
-- 7. Application sequence privilege matrix
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    p text;
BEGIN
    FOR r IN
        SELECT seq_name,
               (seq_name <> 'security_event_retention_runs_id_seq') AS allowed
        FROM unnest(ARRAY[
            'audit_logs_id_seq', 'cart_items_id_seq', 'carts_id_seq',
            'categories_id_seq', 'order_items_id_seq', 'orders_id_seq',
            'payment_proofs_id_seq', 'payments_id_seq', 'product_images_id_seq',
            'product_reviews_id_seq', 'product_variants_id_seq', 'products_id_seq',
            'security_event_retention_holds_id_seq',
            'security_event_retention_runs_id_seq', 'security_events_id_seq',
            'users_id_seq'
        ]::text[]) AS seq_name
    LOOP
        FOR p IN SELECT unnest(ARRAY['USAGE','SELECT','UPDATE']::text[])
        LOOP
            IF has_sequence_privilege('utop14_app', r.seq_name, p)
               <> (r.allowed AND p IN ('USAGE','SELECT')) THEN
                RAISE EXCEPTION
                    'FAIL: app sequence privilege % on % expected=%',
                    p, r.seq_name, (r.allowed AND p IN ('USAGE','SELECT'));
            END IF;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: application sequence privilege matrix';
END $$;

-- ---------------------------------------------------------------------------
-- 8. Retention owner/runner table privilege matrices
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    p text;
BEGIN
    FOR r IN
        SELECT table_name,
               CASE table_name
                   WHEN 'security_events' THEN ARRAY['SELECT','DELETE']::text[]
                   WHEN 'security_event_retention_holds' THEN ARRAY['SELECT']::text[]
                   WHEN 'security_event_retention_runs' THEN ARRAY['SELECT','INSERT']::text[]
                   ELSE ARRAY[]::text[]
               END AS allowed
        FROM unnest(ARRAY[
            'alembic_version','audit_logs','auth_rate_limits','cart_items',
            'carts','categories','order_items','orders','payment_proofs',
            'payments','product_images','product_reviews','product_variants',
            'products','security_event_retention_holds',
            'security_event_retention_runs','security_events','users'
        ]::text[]) AS table_name
    LOOP
        FOR p IN SELECT unnest(
            ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']::text[]
        )
        LOOP
            IF has_table_privilege('utop14_retention_owner', r.table_name, p)
               <> (p = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: retention owner privilege % on % expected=%',
                    p, r.table_name, (p = ANY (r.allowed));
            END IF;
        END LOOP;
    END LOOP;

    FOR r IN
        SELECT table_name,
               CASE table_name
                   WHEN 'security_event_retention_runs' THEN ARRAY['SELECT','INSERT']::text[]
                   ELSE ARRAY[]::text[]
               END AS allowed
        FROM unnest(ARRAY[
            'alembic_version','audit_logs','auth_rate_limits','cart_items',
            'carts','categories','order_items','orders','payment_proofs',
            'payments','product_images','product_reviews','product_variants',
            'products','security_event_retention_holds',
            'security_event_retention_runs','security_events','users'
        ]::text[]) AS table_name
    LOOP
        FOR p IN SELECT unnest(
            ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']::text[]
        )
        LOOP
            IF has_table_privilege('utop14_retention_runner', r.table_name, p)
               <> (p = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: retention runner privilege % on % expected=%',
                    p, r.table_name, (p = ANY (r.allowed));
            END IF;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: retention owner/runner table matrices';
END $$;

-- ---------------------------------------------------------------------------
-- 9. Retention owner/runner sequence matrices
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    p text;
BEGIN
    FOR r IN
        SELECT seq_name,
               (seq_name = 'security_event_retention_runs_id_seq') AS allowed
        FROM unnest(ARRAY[
            'audit_logs_id_seq','cart_items_id_seq','carts_id_seq',
            'categories_id_seq','order_items_id_seq','orders_id_seq',
            'payment_proofs_id_seq','payments_id_seq','product_images_id_seq',
            'product_reviews_id_seq','product_variants_id_seq','products_id_seq',
            'security_event_retention_holds_id_seq',
            'security_event_retention_runs_id_seq','security_events_id_seq',
            'users_id_seq'
        ]::text[]) AS seq_name
    LOOP
        FOR p IN SELECT unnest(ARRAY['USAGE','SELECT','UPDATE']::text[])
        LOOP
            IF has_sequence_privilege('utop14_retention_owner', r.seq_name, p)
               <> (r.allowed AND p IN ('USAGE','SELECT')) THEN
                RAISE EXCEPTION
                    'FAIL: retention owner sequence % on % expected=%',
                    p, r.seq_name, (r.allowed AND p IN ('USAGE','SELECT'));
            END IF;
            IF has_sequence_privilege('utop14_retention_runner', r.seq_name, p)
               <> (r.allowed AND p IN ('USAGE','SELECT')) THEN
                RAISE EXCEPTION
                    'FAIL: retention runner sequence % on % expected=%',
                    p, r.seq_name, (r.allowed AND p IN ('USAGE','SELECT'));
            END IF;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: retention owner/runner sequence matrices';
END $$;

-- ---------------------------------------------------------------------------
-- 10. Function ownership, SECURITY DEFINER, search_path, EXECUTE
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
        RAISE EXCEPTION 'FAIL: prune_security_events owner=%', v_owner;
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

    IF NOT has_function_privilege(
        'utop14_app',
        'public.security_event_retention_holds_lock()',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: app lacks hold-lock trigger EXECUTE';
    END IF;
    IF has_function_privilege(
        'utop14_retention_owner',
        'public.security_event_retention_holds_lock()',
        'EXECUTE'
    ) OR has_function_privilege(
        'utop14_retention_runner',
        'public.security_event_retention_holds_lock()',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: retention role has hold-lock trigger EXECUTE';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_proc p,
             aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE p.oid = 'public.security_event_retention_holds_lock()'::regprocedure
          AND a.grantee = 0
          AND a.privilege_type = 'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: PUBLIC has hold-lock trigger EXECUTE';
    END IF;

    IF has_function_privilege(
        'utop14_app',
        'public.audit_logs_reject_mutation()',
        'EXECUTE'
    ) OR has_function_privilege(
        'utop14_app',
        'public.security_events_reject_mutation()',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION 'FAIL: app has append-only trigger function EXECUTE';
    END IF;

    RAISE NOTICE 'PASS: function ownership, SECURITY DEFINER, EXECUTE';
END $$;

-- ---------------------------------------------------------------------------
-- 11. Append-only trigger presence/enabled and app mutation probes
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = 'audit_logs'
          AND t.tgname = 'audit_logs_append_only'
          AND t.tgenabled = 'O'
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'FAIL: audit_logs append-only trigger is missing/disabled';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger t
        JOIN pg_class c ON c.oid = t.tgrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = 'security_events'
          AND t.tgname = 'security_events_append_only'
          AND t.tgenabled = 'O'
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'FAIL: security_events append-only trigger is missing/disabled';
    END IF;
    RAISE NOTICE 'PASS: append-only triggers enabled';
END $$;

DO $$
BEGIN
    BEGIN
        EXECUTE 'SET LOCAL ROLE utop14_app';
        UPDATE public.audit_logs SET actor_email = actor_email WHERE false;
        RAISE EXCEPTION 'FAIL: app can UPDATE audit_logs';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot UPDATE audit_logs';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    BEGIN
        EXECUTE 'SET LOCAL ROLE utop14_app';
        DELETE FROM public.audit_logs WHERE false;
        RAISE EXCEPTION 'FAIL: app can DELETE audit_logs';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot DELETE audit_logs';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    BEGIN
        EXECUTE 'SET LOCAL ROLE utop14_app';
        UPDATE public.security_events SET user_agent = user_agent WHERE false;
        RAISE EXCEPTION 'FAIL: app can UPDATE security_events';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot UPDATE security_events';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    BEGIN
        EXECUTE 'SET LOCAL ROLE utop14_app';
        DELETE FROM public.security_events WHERE false;
        RAISE EXCEPTION 'FAIL: app can DELETE security_events';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot DELETE security_events';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    EXECUTE 'SET LOCAL ROLE utop14_app';
    BEGIN
        ALTER TABLE public.security_events
            DISABLE TRIGGER security_events_append_only;
        RAISE EXCEPTION 'FAIL: app can disable security_events trigger';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot disable security_events trigger';
    END;
    RESET ROLE;
END $$;

DO $$
BEGIN
    EXECUTE 'SET LOCAL ROLE utop14_app';
    BEGIN
        ALTER TABLE public.audit_logs
            DISABLE TRIGGER audit_logs_append_only;
        RAISE EXCEPTION 'FAIL: app can disable audit_logs trigger';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS: app cannot disable audit_logs trigger';
    END;
    RESET ROLE;
END $$;

-- ---------------------------------------------------------------------------
-- 12. Dangerous default privileges
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
        WHERE d.defaclrole IN ('utop14_app'::regrole,
                               'utop14_retention_owner'::regrole,
                               'utop14_retention_runner'::regrole)
           OR a.grantee IN ('utop14_app'::regrole,
                            'utop14_retention_owner'::regrole,
                            'utop14_retention_runner'::regrole)
           OR a.grantee = 0
    LOOP
        RAISE EXCEPTION
            'FAIL: custom default privilege % on % grants to %',
            r.privilege_type, r.owner_role, r.grantee;
    END LOOP;
    RAISE NOTICE 'PASS: no custom default privileges for app/retention roles/PUBLIC';
END $$;

DO $$
BEGIN
    RAISE NOTICE 'ALL REQUIRED APPLICATION AND RETENTION PRIVILEGE CHECKS PASSED';
END $$;
