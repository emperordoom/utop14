-- UTOP14 comprehensive application and retention privilege verification.
--
-- Run as a PostgreSQL **superuser** (NOT as utop14_app) after:
--   migrations -> ownership template -> role provisioning.
-- Superuser execution is required because the runtime probes use SET ROLE.
-- A non-superuser verifier cannot be a member of utop14_app without violating
-- the default-deny membership model, so the script fails its preflight if the
-- current role is not a superuser.
--
-- The script is read-only except for privilege probes that are rolled back if
-- they unexpectedly succeed.  It exits non-zero on the first failed assertion.
--
-- Replace utop14_app / utop14_schema_owner / public with deployment values if
-- they differ.  Every assertion names its role explicitly.
--
-- Supported PostgreSQL: 16 or newer.  MAINTAIN is checked only on PostgreSQL
-- 17+; on older servers that specific check is skipped with an INFO notice.
-- Parameter ACL checks use pg_parameter_acl and has_parameter_privilege
-- (PostgreSQL 15+); if those are unavailable the verification fails closed.
-- Membership option columns (inherit_option/set_option) are read through
-- to_jsonb and a missing option is treated as TRUE, so older catalogs are
-- handled conservatively.
--
-- Security model enforced here:
--   * default-deny role memberships for utop14_app, utop14_retention_owner
--     and utop14_retention_runner (direct, transitive, INHERIT/SET/ADMIN,
--     predefined, custom and nested paths);
--   * only the allowlisted application schema (public) may exist;
--   * no app/retention CREATE or USAGE outside public, and no database-level
--     CREATE for app/retention roles or PUBLIC;
--   * complete table/sequence/function/trigger/type/extension inventory;
--   * complete table ACL, column ACL, and effective column privilege matrix;
--     no explicit column-level grants for managed roles or PUBLIC;
--   * no GRANT OPTION for managed roles or PUBLIC;
--   * no parameter SET/ALTER SYSTEM grants for managed roles or PUBLIC;
--   * persistent GUC allowlist for managed roles, the schema owner, and the
--     current database; database-wide settings require DBA reconciliation;
--   * complete EXECUTE matrix for every function and PUBLIC;
--   * no custom default privileges for managed roles or PUBLIC;
--   * deterministic search_path for verification itself.

\set ON_ERROR_STOP on
\pset pager off

-- Never resolve application objects or helper functions through a caller-owned
-- schema.  pg_catalog first prevents function shadowing; public is the only
-- application schema.
SET search_path = pg_catalog, public;

-- ---------------------------------------------------------------------------
-- 0. Execution-role preflight
--
-- The runtime probes use SET ROLE utop14_app.  If the verifier cannot do so,
-- that is a hard execution failure, never a PASS for a denied operation.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = current_user AND rolsuper
    ) THEN
        RAISE EXCEPTION
            'FAIL: verification must run as a PostgreSQL superuser; current_user=% cannot assume utop14_app without a forbidden membership',
            current_user;
    END IF;
    RAISE NOTICE 'PASS: verification is running as a superuser';
END $$;

-- ---------------------------------------------------------------------------
-- 1. Role attributes and LOGIN/NOLOGIN
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- The dedicated DDL/schema owner may be a DBA (possibly privileged); the
    -- app and retention roles must not be.  The ownership/membership checks
    -- below still prove the schema owner is separate from those roles.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner',
                          'utop14_app')
          AND (rolsuper OR rolcreatedb OR rolcreaterole
               OR rolreplication OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'FAIL: application/retention role has SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_schema_owner'
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_schema_owner is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_retention_owner' AND NOT rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_retention_owner must exist and be NOLOGIN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_retention_runner' AND rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_retention_runner must exist and be LOGIN';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'utop14_app' AND rolcanlogin
    ) THEN
        RAISE EXCEPTION 'FAIL: utop14_app must exist and be LOGIN';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname IN ('utop14_app',
                          'utop14_retention_owner',
                          'utop14_retention_runner')
          AND rolinherit
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention roles must be NOINHERIT';
    END IF;
    RAISE NOTICE 'PASS: role attributes and LOGIN/NOLOGIN';
END $$;

-- ---------------------------------------------------------------------------
-- 1b. Database-level CREATE and application-role search_path
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
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
        RAISE EXCEPTION 'FAIL: PUBLIC has database-level CREATE';
    END IF;

    FOR r IN
        SELECT pg_catalog.unnest(ARRAY['utop14_app',
                            'utop14_retention_owner',
                            'utop14_retention_runner']) AS role_name
    LOOP
        IF pg_catalog.has_database_privilege(r.role_name, pg_catalog.current_database(), 'CREATE') THEN
            RAISE EXCEPTION
                'FAIL: % has database-level CREATE; CREATE SCHEMA must be denied',
                r.role_name;
        END IF;
    END LOOP;

    -- The application role must not keep the default "$user", public path; a
    -- schema named after the role could otherwise shadow application tables.
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
            'FAIL: utop14_app search_path must be set to public, pg_catalog';
    END IF;

    -- A database-specific role setting overrides the role-level setting.
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
            'FAIL: utop14_app has an overriding database-level search_path; run ALTER ROLE utop14_app IN DATABASE %I RESET search_path',
            pg_catalog.current_database();
    END IF;

    RAISE NOTICE 'PASS: database CREATE denied; app search_path locked';
END $$;

-- ---------------------------------------------------------------------------
-- 1c. Parameter ACLs: no SET or ALTER SYSTEM for managed roles/PUBLIC
--
-- PostgreSQL 15+ catalog.  The project supports PostgreSQL 16+, so absence
-- of the catalog/function is a hard verification failure, not a skip.
-- utop14_schema_owner is a managed principal for explicit parameter ACLs;
-- its implicit superuser privileges, if any, are outside the ACL model.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    p record;
    priv text;
    v_schema_super boolean;
BEGIN
    IF pg_catalog.to_regclass('pg_catalog.pg_parameter_acl') IS NULL
       OR pg_catalog.to_regprocedure(
           'pg_catalog.has_parameter_privilege(name,text,text)'
       ) IS NULL THEN
        RAISE EXCEPTION
            'FAIL: parameter ACL catalog/function support is unavailable; cannot verify parameter privileges';
    END IF;

    SELECT rolsuper INTO v_schema_super
    FROM pg_catalog.pg_roles
    WHERE rolname = 'utop14_schema_owner';

    -- Direct grants to managed roles or PUBLIC, and GRANT OPTION.
    FOR r IN
        SELECT pa.parname,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
               a.privilege_type,
               a.is_grantable
        FROM pg_catalog.pg_parameter_acl pa
        CROSS JOIN LATERAL pg_catalog.aclexplode(pa.paracl) a
        WHERE a.grantee = 0
           OR a.grantee IN ('utop14_app'::regrole,
                            'utop14_retention_owner'::regrole,
                            'utop14_retention_runner'::regrole,
                            'utop14_schema_owner'::regrole)
    LOOP
        IF r.is_grantable THEN
            RAISE EXCEPTION
                'FAIL: parameter privilege % on % to % has GRANT OPTION',
                r.privilege_type, r.parname, r.grantee;
        END IF;
        RAISE EXCEPTION
            'FAIL: parameter privilege % on % granted to %; SET/ALTER SYSTEM are not approved for managed roles or PUBLIC',
            r.privilege_type, r.parname, r.grantee;
    END LOOP;

    -- Effective privileges through membership/PUBLIC/custom-role paths.
    FOR p IN SELECT parname FROM pg_catalog.pg_parameter_acl LOOP
        FOREACH priv IN ARRAY ARRAY['SET', 'ALTER SYSTEM'] LOOP
            IF pg_catalog.has_parameter_privilege(
                'utop14_app', p.parname, priv
            ) THEN
                RAISE EXCEPTION
                    'FAIL: utop14_app has effective parameter % on %',
                    priv, p.parname;
            END IF;
            IF pg_catalog.has_parameter_privilege(
                'utop14_retention_owner', p.parname, priv
            ) THEN
                RAISE EXCEPTION
                    'FAIL: utop14_retention_owner has effective parameter % on %',
                    priv, p.parname;
            END IF;
            IF pg_catalog.has_parameter_privilege(
                'utop14_retention_runner', p.parname, priv
            ) THEN
                RAISE EXCEPTION
                    'FAIL: utop14_retention_runner has effective parameter % on %',
                    priv, p.parname;
            END IF;
            IF NOT v_schema_super
               AND pg_catalog.has_parameter_privilege(
                   'utop14_schema_owner', p.parname, priv
               ) THEN
                RAISE EXCEPTION
                    'FAIL: utop14_schema_owner has effective parameter % on %',
                    priv, p.parname;
            END IF;
        END LOOP;
    END LOOP;

    RAISE NOTICE 'PASS: no managed-role/PUBLIC parameter SET or ALTER SYSTEM privileges';
END $$;

-- ---------------------------------------------------------------------------
-- 1d. Persistent GUC allowlist for managed roles in every database
--
-- Approved:
--   utop14_app role-level: exactly search_path=public, pg_catalog
--   retention roles: no role-level settings
--   schema owner: search_path only (DBA operational need); anything else
--                 requires explicit DBA reconciliation
--   managed role database-specific settings: none in any database
--   database-wide settings (setrole=0): none in any database or globally
--
-- Database-wide settings are never modified by verification; the DBA must
-- reconcile them.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_entry text;
    v_app_entries integer;
    v_app_oid oid := 'utop14_app'::regrole;
    v_owner_oid oid := 'utop14_retention_owner'::regrole;
    v_runner_oid oid := 'utop14_retention_runner'::regrole;
    v_schema_oid oid := 'utop14_schema_owner'::regrole;
BEGIN
    -- App role-level settings must be exactly one approved search_path.
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
            'FAIL: utop14_app role-level settings must be exactly search_path=public, pg_catalog; current=%',
            (SELECT rolconfig FROM pg_catalog.pg_roles WHERE rolname = 'utop14_app');
    END IF;

    -- Retention roles must have no role-level settings.
    FOR r IN
        SELECT rolname, rolconfig
        FROM pg_catalog.pg_roles
        WHERE rolname IN ('utop14_retention_owner',
                          'utop14_retention_runner')
    LOOP
        IF r.rolconfig IS NOT NULL
           AND pg_catalog.array_length(r.rolconfig, 1) > 0 THEN
            RAISE EXCEPTION
                'FAIL: % has unexpected role-level GUC %',
                r.rolname, r.rolconfig;
        END IF;
    END LOOP;

    -- Schema owner: search_path only; other persistent GUCs need DBA approval.
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
                        'FAIL: utop14_schema_owner has unapproved role-level GUC %; DBA reconciliation required',
                        v_entry;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- Managed role-in-database settings must be empty in EVERY database.
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
                'FAIL: % has database-specific GUC % in database %; provisioning must reset it',
                r.role_name, r.setconfig, r.dbname;
        END IF;
    END LOOP;

    -- Schema owner database-specific settings must be search_path only,
    -- regardless of database.
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
                        'FAIL: utop14_schema_owner has unapproved database-specific GUC % in database %; DBA reconciliation required',
                        v_entry, r.dbname;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    -- Database-wide/global settings in ANY database affect application
    -- sessions there.  Fail closed and leave reconciliation to the DBA.
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
                'FAIL: database-wide GUC % in % (setdatabase=%) requires DBA reconciliation; verification will not modify unrelated roles',
                r.setconfig, r.dbname, r.setdatabase;
        END IF;
    END LOOP;

    RAISE NOTICE 'PASS: persistent role/database GUC allowlist for all databases';
END $$;

-- ---------------------------------------------------------------------------
-- 1e. Sensitive cluster-level GUC sources
--
-- postgresql.auto.conf is writable through ALTER SYSTEM.  Detect sensitive
-- settings there even if they are pending restart or the current session has
-- a session-level override.  DBA-managed sources (postgresql.conf, command
-- line, environment) are reported for operational review, not failed.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
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
    r record;
BEGIN
    IF pg_catalog.to_regclass('pg_catalog.pg_settings') IS NULL
       OR pg_catalog.to_regclass('pg_catalog.pg_file_settings') IS NULL THEN
        RAISE EXCEPTION
            'FAIL: pg_settings/pg_file_settings unavailable; cannot verify cluster-level GUC sources';
    END IF;

    FOR r IN
        SELECT name, setting, source, sourcefile, pending_restart
        FROM pg_catalog.pg_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile IS NOT NULL
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: sensitive cluster GUC %=% is configured in postgresql.auto.conf (%); pending_restart=%',
            r.name, r.setting, r.sourcefile, r.pending_restart;
    END LOOP;

    -- pg_file_settings also exposes pending entries and settings hidden by a
    -- session override.
    FOR r IN
        SELECT sourcefile, name, setting, applied, error
        FROM pg_catalog.pg_file_settings
        WHERE name = ANY (v_sensitive)
          AND sourcefile LIKE '%postgresql.auto.conf'
    LOOP
        RAISE EXCEPTION
            'FAIL: postgresql.auto.conf contains sensitive GUC %=% (%); applied=%, error=%',
            r.name, r.setting, r.sourcefile, r.applied, r.error;
    END LOOP;

    FOR r IN
        SELECT name, setting, source, sourcefile, pending_restart
        FROM pg_catalog.pg_settings
        WHERE name = ANY (v_sensitive)
          AND source NOT IN ('default', 'session', 'client', 'override')
          AND (sourcefile IS NULL OR sourcefile NOT LIKE '%postgresql.auto.conf')
    LOOP
        RAISE NOTICE
            'INFO: cluster GUC %=% source=% file=% pending_restart=% requires DBA review',
            r.name, r.setting, r.source, r.sourcefile, r.pending_restart;
    END LOOP;

    RAISE NOTICE 'PASS: no sensitive cluster GUCs in postgresql.auto.conf';
END $$;

-- ---------------------------------------------------------------------------
-- 2. Extension, schema, type and object inventory (fail closed)
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
    v_count integer;
BEGIN
    -- Extensions: plpgsql is the only approved extension.  A new extension
    -- must be reviewed and added to this allowlist (and to the provisioning
    -- preflight) before it can pass verification.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'plpgsql') THEN
        RAISE EXCEPTION 'FAIL: required extension plpgsql is missing';
    END IF;
    SELECT pg_catalog.array_agg(extname ORDER BY extname) INTO extra
    FROM pg_catalog.pg_extension
    WHERE NOT (extname = ANY (expected_extensions));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried extensions %; review them and add to the allowlist',
            extra;
    END IF;

    -- Non-system schemas.  Extension-owned schemas are not application
    -- objects and are excluded; every other schema must be the allowlisted
    -- application schema.
    SELECT pg_catalog.array_agg(n.nspname ORDER BY n.nspname) INTO extra
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
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried non-system schemas %; review them and add to the allowlist',
            extra;
    END IF;
    SELECT pg_catalog.array_agg(s ORDER BY s) INTO missing
    FROM pg_catalog.unnest(expected_schemas) s
    WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = s);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected schemas %', missing;
    END IF;

    -- User-defined types/domains/enums/composites.  Table row types and
    -- implicit array types are not user-created objects; extension-owned
    -- types are excluded so an approved extension is not misclassified.
    SELECT pg_catalog.array_agg(pg_catalog.format('%I.%I', n.nspname, t.typname) ORDER BY 1) INTO extra
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
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: uninventoried user-defined types/domains %; add them to the inventory and privilege model',
            extra;
    END IF;

    SELECT pg_catalog.array_agg(t ORDER BY t) INTO missing
    FROM pg_catalog.unnest(expected_tables) t
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = t
          AND c.relkind IN ('r', 'p', 'f')
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected tables %', missing;
    END IF;
    SELECT pg_catalog.array_agg(c.relname ORDER BY c.relname) INTO extra
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
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried tables %', extra;
    END IF;

    SELECT pg_catalog.array_agg(s ORDER BY s) INTO missing
    FROM pg_catalog.unnest(expected_sequences) s
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = s AND c.relkind = 'S'
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected sequences %', missing;
    END IF;
    SELECT pg_catalog.array_agg(c.relname ORDER BY c.relname) INTO extra
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
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried sequences %', extra;
    END IF;

    FOREACH fn IN ARRAY expected_functions LOOP
        IF fn = 'prune_security_events' THEN
            SELECT pg_catalog.count(*) INTO v_count
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = fn
              AND p.pronargs = 5 AND p.prokind = 'f';
        ELSE
            SELECT pg_catalog.count(*) INTO v_count
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = fn
              AND p.pronargs = 0 AND p.prokind = 'f';
        END IF;
        IF v_count <> 1 THEN
            RAISE EXCEPTION
                'FAIL: expected exactly one function signature for %, found %',
                fn, v_count;
        END IF;
    END LOOP;
    SELECT pg_catalog.array_agg(p.proname ORDER BY p.proname) INTO extra
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND NOT (p.proname = ANY (expected_functions))
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
      );
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried functions/procedures %', extra;
    END IF;

    SELECT pg_catalog.array_agg(t) INTO missing
    FROM pg_catalog.unnest(expected_triggers) t
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger tr
        JOIN pg_catalog.pg_class c ON c.oid = tr.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND tr.tgname = t AND NOT tr.tgisinternal
    );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: missing expected triggers %', missing;
    END IF;
    SELECT pg_catalog.array_agg(tr.tgname ORDER BY tr.tgname) INTO extra
    FROM pg_catalog.pg_trigger tr
    JOIN pg_catalog.pg_class c ON c.oid = tr.tgrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY (expected_tables)
      AND NOT tr.tgisinternal
      AND NOT (tr.tgname = ANY (expected_triggers));
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried triggers %', extra;
    END IF;

    -- No application views or materialized views.  Extension-owned views are
    -- excluded so an approved extension is not misclassified.
    SELECT pg_catalog.array_agg(pg_catalog.format('%I.%I', n.nspname, c.relname) ORDER BY 1) INTO extra
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ANY (expected_schemas)
      AND c.relkind IN ('v', 'm')
      AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.pg_depend d
          WHERE d.classid = 'pg_catalog.pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e'
      );
    IF extra IS NOT NULL THEN
        RAISE EXCEPTION 'FAIL: uninventoried views/materialized views %', extra;
    END IF;

    RAISE NOTICE 'PASS: extension/schema/type/object inventory';
END $$;

-- ---------------------------------------------------------------------------
-- 3. Ownership inventory
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_owner text;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(datdba) INTO v_owner
    FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database();
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION 'FAIL: database owner=% (expected utop14_schema_owner)', v_owner;
    END IF;

    SELECT nspowner::regrole::text INTO v_owner
    FROM pg_catalog.pg_namespace WHERE nspname = 'public';
    IF v_owner IS DISTINCT FROM 'utop14_schema_owner' THEN
        RAISE EXCEPTION 'FAIL: schema public owner=% (expected utop14_schema_owner)', v_owner;
    END IF;

    FOR r IN
        SELECT c.relname AS tablename, pg_catalog.pg_get_userbyid(c.relowner) AS tableowner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'f')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        IF r.tableowner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: table % owner=%', r.tablename, r.tableowner;
        END IF;
    END LOOP;

    FOR r IN
        SELECT c.relname, pg_catalog.pg_get_userbyid(c.relowner) AS owner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'S'
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    LOOP
        IF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: sequence % owner=%', r.relname, r.owner;
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
        IF r.proname = 'prune_security_events' THEN
            IF r.owner IS DISTINCT FROM 'utop14_retention_owner' THEN
                RAISE EXCEPTION 'FAIL: prune_security_events owner=%', r.owner;
            END IF;
        ELSIF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
            RAISE EXCEPTION 'FAIL: helper function % owner=%', r.proname, r.owner;
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f', 'S')
          AND pg_catalog.pg_get_userbyid(c.relowner) IN ('utop14_app',
                                              'utop14_retention_owner',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/retention role owns an application table or sequence';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND pg_catalog.pg_get_userbyid(p.proowner) IN ('utop14_app',
                                              'utop14_retention_runner')
    ) THEN
        RAISE EXCEPTION 'FAIL: app/runner role owns an application function';
    END IF;

    RAISE NOTICE 'PASS: ownership inventory';
END $$;

-- ---------------------------------------------------------------------------
-- 4. Default-deny membership / SET ROLE escalation paths
--
-- Explicit membership allowlist.  It is intentionally empty: the current
-- model requires no role memberships for the app or either retention role.
-- Add "member:granted_role" entries here ONLY after a documented review and
-- a matching allowlist change in the provisioning script.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_allowed text[] := ARRAY[]::text[];
    v_member text;
    v_role text;
    v_path text;
    v_inherit text;
    v_set text;
    v_admin text;
    v_reverse_member text;
    v_reverse_role text;
BEGIN
    WITH RECURSIVE edges AS (
        SELECT m.member AS member_oid,
               m.roleid AS role_oid,
               r.rolname AS member_name,
               g.rolname AS role_name,
               COALESCE((pg_catalog.to_jsonb(m) ->> 'inherit_option')::boolean, TRUE)
                   AS inherit_opt,
               COALESCE((pg_catalog.to_jsonb(m) ->> 'set_option')::boolean, TRUE)
                   AS set_opt,
               COALESCE((pg_catalog.to_jsonb(m) ->> 'admin_option')::boolean, FALSE)
                   AS admin_opt
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles r ON r.oid = m.member
        JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
    ),
    managed(rolname) AS (
        VALUES ('utop14_app'),
               ('utop14_retention_owner'),
               ('utop14_retention_runner')
    ),
    walk AS (
        SELECT e.member_name,
               e.role_name,
               ARRAY[e.member_name, e.role_name] AS path,
               1 AS depth,
               e.inherit_opt,
               e.set_opt,
               e.admin_opt
        FROM edges e
        JOIN managed md ON md.rolname = e.member_name
        UNION ALL
        SELECT w.member_name,
               e.role_name,
               w.path || e.role_name,
               w.depth + 1,
               w.inherit_opt OR e.inherit_opt,
               w.set_opt OR e.set_opt,
               w.admin_opt OR e.admin_opt
        FROM walk w
        JOIN edges e ON e.member_name = w.role_name
        WHERE NOT (e.role_name = ANY (w.path))
    )
    SELECT member_name,
           role_name,
           pg_catalog.array_to_string(path, ' -> '),
           CASE WHEN inherit_opt THEN 'true' ELSE 'false' END,
           CASE WHEN set_opt THEN 'true' ELSE 'false' END,
           CASE WHEN admin_opt THEN 'true' ELSE 'false' END
      INTO v_member, v_role, v_path, v_inherit, v_set, v_admin
      FROM walk
     WHERE NOT (member_name || ':' || role_name = ANY (v_allowed))
     ORDER BY depth DESC, member_name, role_name
     LIMIT 1;

    IF v_member IS NOT NULL THEN
        RAISE EXCEPTION
            'FAIL: forbidden role membership path % (inherit=%, set=%, admin=%); default-deny: run REVOKE % FROM % and add to the documented allowlist only if operationally required',
            v_path, v_inherit, v_set, v_admin,
            pg_catalog.quote_ident(v_role), pg_catalog.quote_ident(v_member);
    END IF;

    -- Reverse direction: another role must not be able to assume a managed
    -- role.  Managed-to-managed edges are already covered above.
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
            'FAIL: forbidden reverse membership % -> %; another role can assume a managed role. Run REVOKE % FROM % manually and document the dependency',
            v_reverse_member, v_reverse_role,
            pg_catalog.quote_ident(v_reverse_role), pg_catalog.quote_ident(v_reverse_member);
    END IF;

    RAISE NOTICE 'PASS: default-deny role memberships';
END $$;

-- ---------------------------------------------------------------------------
-- 5. Schema privileges for every non-system schema
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    v_public_create integer;
BEGIN
    FOR r IN
        SELECT n.nspname
        FROM pg_catalog.pg_namespace n
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
    LOOP
        IF pg_catalog.has_schema_privilege('utop14_app', r.nspname, 'CREATE') THEN
            RAISE EXCEPTION 'FAIL: utop14_app has CREATE on schema %', r.nspname;
        END IF;
        IF pg_catalog.has_schema_privilege('utop14_retention_owner', r.nspname, 'CREATE')
           OR pg_catalog.has_schema_privilege('utop14_retention_runner', r.nspname, 'CREATE') THEN
            RAISE EXCEPTION 'FAIL: retention role has CREATE on schema %', r.nspname;
        END IF;
        IF r.nspname <> 'public' AND (
            pg_catalog.has_schema_privilege('utop14_app', r.nspname, 'USAGE')
            OR pg_catalog.has_schema_privilege('utop14_retention_owner', r.nspname, 'USAGE')
            OR pg_catalog.has_schema_privilege('utop14_retention_runner', r.nspname, 'USAGE')
        ) THEN
            RAISE EXCEPTION
                'FAIL: app/retention role has USAGE on non-application schema %',
                r.nspname;
        END IF;

        SELECT pg_catalog.count(*) INTO v_public_create
        FROM pg_catalog.aclexplode(
            COALESCE(
                (SELECT nspacl FROM pg_catalog.pg_namespace WHERE nspname = r.nspname),
                pg_catalog.acldefault(
                    'n',
                    (SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname = r.nspname)
                )
            )
        ) a
        WHERE a.grantee = 0 AND a.privilege_type = 'CREATE';
        IF v_public_create > 0 THEN
            RAISE EXCEPTION 'FAIL: PUBLIC has CREATE on schema %', r.nspname;
        END IF;
    END LOOP;

    IF NOT pg_catalog.has_schema_privilege('utop14_app', 'public', 'USAGE')
       OR NOT pg_catalog.has_schema_privilege('utop14_retention_owner', 'public', 'USAGE')
       OR NOT pg_catalog.has_schema_privilege('utop14_retention_runner', 'public', 'USAGE')
       OR NOT pg_catalog.has_schema_privilege('utop14_schema_owner', 'public', 'USAGE') THEN
        RAISE EXCEPTION 'FAIL: application/retention role lacks schema USAGE';
    END IF;
    IF NOT pg_catalog.has_schema_privilege('utop14_schema_owner', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'FAIL: schema owner lacks schema CREATE';
    END IF;
    RAISE NOTICE 'PASS: schema USAGE/CREATE for all non-system schemas';
END $$;

-- ---------------------------------------------------------------------------
-- 5b. No schema GRANT OPTION for non-owner grantees
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT n.nspname,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
               a.privilege_type
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(n.nspacl, pg_catalog.acldefault('n', n.nspowner))
        ) a
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND a.grantee <> n.nspowner
          AND a.is_grantable
    LOOP
        RAISE EXCEPTION
            'FAIL: schema privilege % on % to % has GRANT OPTION',
            r.privilege_type, r.nspname, r.grantee;
    END LOOP;
    RAISE NOTICE 'PASS: no non-owner schema GRANT OPTION';
END $$;

-- ---------------------------------------------------------------------------
-- 6. Application table and effective column privilege matrix
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    col record;
    p text;
    cp text;
    v_server_num integer := pg_catalog.current_setting('server_version_num')::integer;
    v_table_privs text[] := ARRAY[
        'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES'
    ];
    v_column_privs text[] := ARRAY['SELECT','INSERT','UPDATE','REFERENCES'];
BEGIN
    IF v_server_num >= 170000 THEN
        v_table_privs := array_append(v_table_privs, 'MAINTAIN');
    ELSE
        RAISE NOTICE
            'INFO: MAINTAIN privilege is not available on this PostgreSQL version; skipping that specific check';
    END IF;

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
        FOR p IN SELECT pg_catalog.unnest(v_table_privs)
        LOOP
            IF pg_catalog.has_table_privilege(
                'utop14_app', pg_catalog.format('public.%I', r.table_name), p
            ) <> (p = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: app privilege % on % expected=%',
                    p, r.table_name, (p = ANY (r.allowed));
            END IF;
        END LOOP;

        -- Table-level grants legitimately apply to every column.  Compare the
        -- effective column privilege with the same approved matrix so a
        -- column-only grant on a table with no table-level privilege fails.
        FOREACH cp IN ARRAY v_column_privs LOOP
            IF pg_catalog.has_any_column_privilege(
                'utop14_app', pg_catalog.format('public.%I', r.table_name), cp
            ) <> (cp = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: app any-column privilege % on % expected=%',
                    cp, r.table_name, (cp = ANY (r.allowed));
            END IF;
        END LOOP;
        FOR col IN
            SELECT c.oid AS table_oid, a.attname
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = r.table_name
              AND c.relkind IN ('r', 'p', 'f')
              AND a.attnum > 0
              AND NOT a.attisdropped
        LOOP
            FOREACH cp IN ARRAY v_column_privs LOOP
                IF pg_catalog.has_column_privilege(
                    'utop14_app', col.table_oid, col.attname, cp
                ) <> (cp = ANY (r.allowed)) THEN
                    RAISE EXCEPTION
                        'FAIL: app column privilege % on %.% expected=%',
                        cp, r.table_name, col.attname, (cp = ANY (r.allowed));
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;
    RAISE NOTICE 'PASS: application table and effective column privilege matrix';
END $$;

-- ---------------------------------------------------------------------------
-- 6b. Complete table ACL, column ACL, and retention-role column matrix
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    col record;
    cp text;
    v_column_privs text[] := ARRAY['SELECT','INSERT','UPDATE','REFERENCES'];
BEGIN
    -- Every non-owner table ACL entry must belong to a managed role and carry
    -- an explicitly approved privilege.  PUBLIC and custom grantees are never
    -- allowed.  This catches MAINTAIN and any other privilege not in the matrix.
    FOR r IN
        WITH matrix(table_name, app_allowed, owner_allowed, runner_allowed) AS (
            VALUES
                ('alembic_version', ARRAY[]::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('audit_logs', ARRAY['SELECT','INSERT']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('auth_rate_limits', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('cart_items', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('carts', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('categories', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('order_items', ARRAY['SELECT','INSERT']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('orders', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('payment_proofs', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('payments', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('product_images', ARRAY['SELECT','INSERT','UPDATE','DELETE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('product_reviews', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('product_variants', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('products', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[]),
                ('security_event_retention_holds', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY['SELECT']::text[], ARRAY[]::text[]),
                ('security_event_retention_runs', ARRAY[]::text[], ARRAY['SELECT','INSERT']::text[], ARRAY['SELECT','INSERT']::text[]),
                ('security_events', ARRAY['SELECT','INSERT']::text[], ARRAY['SELECT','DELETE']::text[], ARRAY[]::text[]),
                ('users', ARRAY['SELECT','INSERT','UPDATE']::text[], ARRAY[]::text[], ARRAY[]::text[])
        )
        SELECT c.relname AS table_name,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
               a.privilege_type,
               a.is_grantable,
               m.app_allowed,
               m.owner_allowed,
               m.runner_allowed
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN matrix m ON m.table_name = c.relname
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))
        ) a
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f')
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
          AND a.grantee <> c.relowner
    LOOP
        IF r.is_grantable THEN
            RAISE EXCEPTION
                'FAIL: table privilege % on % to % has GRANT OPTION',
                r.privilege_type, r.table_name, r.grantee;
        END IF;
        IF r.grantee = 'PUBLIC' THEN
            RAISE EXCEPTION
                'FAIL: PUBLIC has table privilege % on %',
                r.privilege_type, r.table_name;
        ELSIF r.grantee = 'utop14_app' THEN
            IF NOT (r.privilege_type = ANY (r.app_allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected app table privilege % on %',
                    r.privilege_type, r.table_name;
            END IF;
        ELSIF r.grantee = 'utop14_retention_owner' THEN
            IF NOT (r.privilege_type = ANY (r.owner_allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected retention-owner table privilege % on %',
                    r.privilege_type, r.table_name;
            END IF;
        ELSIF r.grantee = 'utop14_retention_runner' THEN
            IF NOT (r.privilege_type = ANY (r.runner_allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected retention-runner table privilege % on %',
                    r.privilege_type, r.table_name;
            END IF;
        ELSE
            RAISE EXCEPTION
                'FAIL: unexpected table grantee % with privilege % on %',
                r.grantee, r.privilege_type, r.table_name;
        END IF;
    END LOOP;

    -- No explicit column-level grant is approved for any non-owner grantee.
    -- This catches redundant grants (where table-level access already exists)
    -- as well as grants on tables/columns the role must not access at all.
    FOR r IN
        SELECT c.relname AS table_name,
               a.attname AS column_name,
               CASE WHEN x.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(x.grantee) END AS grantee,
               x.privilege_type,
               x.is_grantable
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) x
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND a.attacl IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
          AND x.grantee <> c.relowner
    LOOP
        RAISE EXCEPTION
            'FAIL: unexpected column ACL % on %.% to % (grant_option=%); column-level grants are not in the approved matrix',
            r.privilege_type, r.table_name, r.column_name,
            r.grantee, r.is_grantable;
    END LOOP;

    -- Effective column privileges for the retention roles must match their
    -- approved table-level matrices.  Table-level grants legitimately apply to
    -- every column; a column-only grant on another table/column fails.
    FOR r IN
        SELECT table_name, allowed FROM (VALUES
            ('alembic_version', ARRAY[]::text[]),
            ('audit_logs', ARRAY[]::text[]),
            ('auth_rate_limits', ARRAY[]::text[]),
            ('cart_items', ARRAY[]::text[]),
            ('carts', ARRAY[]::text[]),
            ('categories', ARRAY[]::text[]),
            ('order_items', ARRAY[]::text[]),
            ('orders', ARRAY[]::text[]),
            ('payment_proofs', ARRAY[]::text[]),
            ('payments', ARRAY[]::text[]),
            ('product_images', ARRAY[]::text[]),
            ('product_reviews', ARRAY[]::text[]),
            ('product_variants', ARRAY[]::text[]),
            ('products', ARRAY[]::text[]),
            ('security_event_retention_holds', ARRAY['SELECT']::text[]),
            ('security_event_retention_runs', ARRAY['SELECT','INSERT']::text[]),
            ('security_events', ARRAY['SELECT','DELETE']::text[]),
            ('users', ARRAY[]::text[])
        ) AS t(table_name, allowed)
    LOOP
        FOREACH cp IN ARRAY v_column_privs LOOP
            IF pg_catalog.has_any_column_privilege(
                'utop14_retention_owner', pg_catalog.format('public.%I', r.table_name), cp
            ) <> (cp = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: retention-owner any-column privilege % on % expected=%',
                    cp, r.table_name, (cp = ANY (r.allowed));
            END IF;
        END LOOP;
        FOR col IN
            SELECT c.oid AS table_oid, a.attname
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = r.table_name
              AND c.relkind IN ('r', 'p', 'f')
              AND a.attnum > 0
              AND NOT a.attisdropped
        LOOP
            FOREACH cp IN ARRAY v_column_privs LOOP
                IF pg_catalog.has_column_privilege(
                    'utop14_retention_owner', col.table_oid, col.attname, cp
                ) <> (cp = ANY (r.allowed)) THEN
                    RAISE EXCEPTION
                        'FAIL: retention-owner column privilege % on %.% expected=%',
                        cp, r.table_name, col.attname, (cp = ANY (r.allowed));
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;

    FOR r IN
        SELECT table_name, allowed FROM (VALUES
            ('alembic_version', ARRAY[]::text[]),
            ('audit_logs', ARRAY[]::text[]),
            ('auth_rate_limits', ARRAY[]::text[]),
            ('cart_items', ARRAY[]::text[]),
            ('carts', ARRAY[]::text[]),
            ('categories', ARRAY[]::text[]),
            ('order_items', ARRAY[]::text[]),
            ('orders', ARRAY[]::text[]),
            ('payment_proofs', ARRAY[]::text[]),
            ('payments', ARRAY[]::text[]),
            ('product_images', ARRAY[]::text[]),
            ('product_reviews', ARRAY[]::text[]),
            ('product_variants', ARRAY[]::text[]),
            ('products', ARRAY[]::text[]),
            ('security_event_retention_holds', ARRAY[]::text[]),
            ('security_event_retention_runs', ARRAY['SELECT','INSERT']::text[]),
            ('security_events', ARRAY[]::text[]),
            ('users', ARRAY[]::text[])
        ) AS t(table_name, allowed)
    LOOP
        FOREACH cp IN ARRAY v_column_privs LOOP
            IF pg_catalog.has_any_column_privilege(
                'utop14_retention_runner', pg_catalog.format('public.%I', r.table_name), cp
            ) <> (cp = ANY (r.allowed)) THEN
                RAISE EXCEPTION
                    'FAIL: retention-runner any-column privilege % on % expected=%',
                    cp, r.table_name, (cp = ANY (r.allowed));
            END IF;
        END LOOP;
        FOR col IN
            SELECT c.oid AS table_oid, a.attname
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = r.table_name
              AND c.relkind IN ('r', 'p', 'f')
              AND a.attnum > 0
              AND NOT a.attisdropped
        LOOP
            FOREACH cp IN ARRAY v_column_privs LOOP
                IF pg_catalog.has_column_privilege(
                    'utop14_retention_runner', col.table_oid, col.attname, cp
                ) <> (cp = ANY (r.allowed)) THEN
                    RAISE EXCEPTION
                        'FAIL: retention-runner column privilege % on %.% expected=%',
                        cp, r.table_name, col.attname, (cp = ANY (r.allowed));
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;

    RAISE NOTICE 'PASS: complete table and column ACL matrix';
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
        FROM pg_catalog.unnest(ARRAY[
            'audit_logs_id_seq', 'cart_items_id_seq', 'carts_id_seq',
            'categories_id_seq', 'order_items_id_seq', 'orders_id_seq',
            'payment_proofs_id_seq', 'payments_id_seq', 'product_images_id_seq',
            'product_reviews_id_seq', 'product_variants_id_seq', 'products_id_seq',
            'security_event_retention_holds_id_seq',
            'security_event_retention_runs_id_seq', 'security_events_id_seq',
            'users_id_seq'
        ]::text[]) AS seq_name
    LOOP
        FOR p IN SELECT pg_catalog.unnest(ARRAY['USAGE','SELECT','UPDATE']::text[])
        LOOP
            IF pg_catalog.has_sequence_privilege(
                'utop14_app', pg_catalog.format('public.%I', r.seq_name), p
            )
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
        FROM pg_catalog.unnest(ARRAY[
            'alembic_version','audit_logs','auth_rate_limits','cart_items',
            'carts','categories','order_items','orders','payment_proofs',
            'payments','product_images','product_reviews','product_variants',
            'products','security_event_retention_holds',
            'security_event_retention_runs','security_events','users'
        ]::text[]) AS table_name
    LOOP
        FOR p IN SELECT pg_catalog.unnest(
            ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']::text[]
        )
        LOOP
            IF pg_catalog.has_table_privilege('utop14_retention_owner', r.table_name, p)
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
        FROM pg_catalog.unnest(ARRAY[
            'alembic_version','audit_logs','auth_rate_limits','cart_items',
            'carts','categories','order_items','orders','payment_proofs',
            'payments','product_images','product_reviews','product_variants',
            'products','security_event_retention_holds',
            'security_event_retention_runs','security_events','users'
        ]::text[]) AS table_name
    LOOP
        FOR p IN SELECT pg_catalog.unnest(
            ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER','REFERENCES']::text[]
        )
        LOOP
            IF pg_catalog.has_table_privilege('utop14_retention_runner', r.table_name, p)
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
        FROM pg_catalog.unnest(ARRAY[
            'audit_logs_id_seq','cart_items_id_seq','carts_id_seq',
            'categories_id_seq','order_items_id_seq','orders_id_seq',
            'payment_proofs_id_seq','payments_id_seq','product_images_id_seq',
            'product_reviews_id_seq','product_variants_id_seq','products_id_seq',
            'security_event_retention_holds_id_seq',
            'security_event_retention_runs_id_seq','security_events_id_seq',
            'users_id_seq'
        ]::text[]) AS seq_name
    LOOP
        FOR p IN SELECT pg_catalog.unnest(ARRAY['USAGE','SELECT','UPDATE']::text[])
        LOOP
            IF pg_catalog.has_sequence_privilege(
                'utop14_retention_owner', pg_catalog.format('public.%I', r.seq_name), p
            )
               <> (r.allowed AND p IN ('USAGE','SELECT')) THEN
                RAISE EXCEPTION
                    'FAIL: retention owner sequence % on % expected=%',
                    p, r.seq_name, (r.allowed AND p IN ('USAGE','SELECT'));
            END IF;
            IF pg_catalog.has_sequence_privilege(
                'utop14_retention_runner', pg_catalog.format('public.%I', r.seq_name), p
            )
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
-- 9b. Complete sequence ACL matrix
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT c.relname AS seq_name,
               CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                    ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
               a.privilege_type,
               a.is_grantable
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(c.relacl, pg_catalog.acldefault('s', c.relowner))
        ) a
        WHERE n.nspname = 'public'
          AND c.relkind = 'S'
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_depend d
              WHERE d.classid = 'pg_catalog.pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
          AND a.grantee <> c.relowner
    LOOP
        IF r.is_grantable THEN
            RAISE EXCEPTION
                'FAIL: sequence privilege % on % to % has GRANT OPTION',
                r.privilege_type, r.seq_name, r.grantee;
        END IF;
        IF r.grantee = 'PUBLIC' THEN
            RAISE EXCEPTION
                'FAIL: PUBLIC has sequence privilege % on %',
                r.privilege_type, r.seq_name;
        ELSIF r.grantee = 'utop14_app' THEN
            IF r.seq_name = 'security_event_retention_runs_id_seq'
               OR NOT (r.privilege_type = ANY (ARRAY['USAGE','SELECT'])) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected app sequence privilege % on %',
                    r.privilege_type, r.seq_name;
            END IF;
        ELSIF r.grantee IN ('utop14_retention_owner',
                            'utop14_retention_runner') THEN
            IF r.seq_name <> 'security_event_retention_runs_id_seq'
               OR NOT (r.privilege_type = ANY (ARRAY['USAGE','SELECT'])) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected retention sequence privilege % on % to %',
                    r.privilege_type, r.seq_name, r.grantee;
            END IF;
        ELSE
            RAISE EXCEPTION
                'FAIL: unexpected sequence grantee % with privilege % on %',
                r.grantee, r.privilege_type, r.seq_name;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: complete sequence ACL matrix';
END $$;

-- ---------------------------------------------------------------------------
-- 10. Function ownership, SECURITY DEFINER, search_path and EXECUTE matrix
--
-- Expected EXECUTE grantees:
--   prune_security_events            -> utop14_retention_runner (and owner)
--   every trigger/helper function    -> owning utop14_schema_owner only
-- utop14_app and PUBLIC never receive EXECUTE.  The hold-lock trigger function
-- needs no app EXECUTE: PostgreSQL checks EXECUTE when the trigger is created,
-- and ordinary INSERT/UPDATE firing needs no direct function privilege.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    r record;
    a record;
    v_expected text[];
BEGIN
    FOR r IN
        SELECT p.oid,
               p.proname,
               p.pronargs,
               p.prokind,
               p.prosecdef,
               p.proconfig,
               p.proowner,
               p.proacl,
               pg_catalog.pg_get_userbyid(p.proowner) AS owner
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
            IF r.pronargs <> 5 OR r.prokind <> 'f' THEN
                RAISE EXCEPTION 'FAIL: prune_security_events signature is invalid';
            END IF;            IF r.owner IS DISTINCT FROM 'utop14_retention_owner' THEN
                RAISE EXCEPTION 'FAIL: prune_security_events owner=%', r.owner;
            END IF;
            IF r.prosecdef IS NOT TRUE THEN
                RAISE EXCEPTION 'FAIL: prune_security_events is not SECURITY DEFINER';
            END IF;
            IF r.proconfig IS NULL
               OR NOT EXISTS (
                   SELECT 1 FROM pg_catalog.unnest(r.proconfig) c
                   WHERE c LIKE 'search_path=pg_catalog%'
               ) THEN
                RAISE EXCEPTION 'FAIL: prune_security_events search_path is not locked to pg_catalog';
            END IF;
            v_expected := ARRAY['utop14_retention_owner',
                                'utop14_retention_runner'];
        ELSIF r.proname IN (
            'audit_logs_reject_mutation',
            'security_events_reject_mutation',
            'security_event_retention_holds_lock'
        ) THEN
            IF r.pronargs <> 0 OR r.prokind <> 'f' THEN
                RAISE EXCEPTION 'FAIL: trigger function % signature is invalid', r.proname;
            END IF;
            IF r.owner IS DISTINCT FROM 'utop14_schema_owner' THEN
                RAISE EXCEPTION 'FAIL: trigger/helper function % owner=%', r.proname, r.owner;
            END IF;
            IF r.prosecdef IS TRUE THEN
                RAISE EXCEPTION 'FAIL: trigger/helper function % must not be SECURITY DEFINER', r.proname;
            END IF;
            IF r.proname = 'security_event_retention_holds_lock'
               AND (
                   r.proconfig IS NULL
                   OR NOT EXISTS (
                       SELECT 1 FROM pg_catalog.unnest(r.proconfig) c
                       WHERE c LIKE 'search_path=pg_catalog%'
                   )
               ) THEN
                RAISE EXCEPTION 'FAIL: hold-lock trigger search_path is not locked to pg_catalog';
            END IF;
            v_expected := ARRAY['utop14_schema_owner'];
        ELSE
            RAISE EXCEPTION 'FAIL: uninventoried function %', r.proname;
        END IF;

        FOR a IN
            SELECT CASE WHEN x.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(x.grantee) END AS grantee,
                   x.privilege_type,
                   x.is_grantable
            FROM pg_catalog.aclexplode(
                COALESCE(r.proacl, pg_catalog.acldefault('f', r.proowner))
            ) x
        LOOP
            IF a.is_grantable THEN
                RAISE EXCEPTION
                    'FAIL: function % privilege % to % has GRANT OPTION',
                    r.proname, a.privilege_type, a.grantee;
            END IF;
            IF a.grantee = 'PUBLIC' THEN
                RAISE EXCEPTION
                    'FAIL: PUBLIC has % on function %',
                    a.privilege_type, r.proname;
            END IF;
            IF a.grantee <> ALL (v_expected) THEN
                RAISE EXCEPTION
                    'FAIL: unexpected % grant on function % to %',
                    a.privilege_type, r.proname, a.grantee;
            END IF;
        END LOOP;

        IF pg_catalog.has_function_privilege('utop14_app'::name, r.oid, 'EXECUTE') THEN
            RAISE EXCEPTION 'FAIL: utop14_app has EXECUTE on function %', r.proname;
        END IF;
        IF r.proname = 'prune_security_events' THEN
            IF NOT pg_catalog.has_function_privilege(
                'utop14_retention_runner'::name, r.oid, 'EXECUTE'
            ) THEN
                RAISE EXCEPTION 'FAIL: runner lacks prune_security_events EXECUTE';
            END IF;
        ELSE
            IF pg_catalog.has_function_privilege(
                'utop14_retention_owner'::name, r.oid, 'EXECUTE'
            ) THEN
                RAISE EXCEPTION
                    'FAIL: retention owner has EXECUTE on unrelated function %',
                    r.proname;
            END IF;
            IF pg_catalog.has_function_privilege(
                'utop14_retention_runner'::name, r.oid, 'EXECUTE'
            ) THEN
                RAISE EXCEPTION
                    'FAIL: retention runner has EXECUTE on unrelated function %',
                    r.proname;
            END IF;
        END IF;
    END LOOP;
    RAISE NOTICE 'PASS: function ownership, SECURITY DEFINER, search_path, EXECUTE matrix';
END $$;

-- ---------------------------------------------------------------------------
-- 11. Append-only trigger presence/enabled and app mutation probes
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = 'audit_logs'
          AND t.tgname = 'audit_logs_append_only'
          AND t.tgenabled = 'O'
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'FAIL: audit_logs append-only trigger is missing/disabled';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = 'security_events'
          AND t.tgname = 'security_events_append_only'
          AND t.tgenabled = 'O'
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'FAIL: security_events append-only trigger is missing/disabled';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = 'security_event_retention_holds'
          AND t.tgname = 'security_event_retention_holds_lock'
          AND t.tgenabled = 'O'
          AND NOT t.tgisinternal
    ) THEN
        RAISE EXCEPTION 'FAIL: hold-lock trigger is missing/disabled';
    END IF;
    RAISE NOTICE 'PASS: append-only and hold-lock triggers enabled';
END $$;

DO $$
BEGIN
    BEGIN
        EXECUTE 'SET LOCAL ROLE utop14_app';
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION
            'FAIL: verifier cannot SET ROLE utop14_app; run verification as a PostgreSQL superuser';
    END;
    BEGIN
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
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION
            'FAIL: verifier cannot SET ROLE utop14_app; run verification as a PostgreSQL superuser';
    END;
    BEGIN
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
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION
            'FAIL: verifier cannot SET ROLE utop14_app; run verification as a PostgreSQL superuser';
    END;
    BEGIN
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
    EXCEPTION WHEN insufficient_privilege THEN
        RAISE EXCEPTION
            'FAIL: verifier cannot SET ROLE utop14_app; run verification as a PostgreSQL superuser';
    END;
    BEGIN
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
            'FAIL: custom default privilege % on % grants to %',
            r.privilege_type, r.owner_role, r.grantee;
    END LOOP;
    RAISE NOTICE 'PASS: no custom default privileges for app/retention roles/PUBLIC';
END $$;

DO $$
BEGIN
    RAISE NOTICE 'ALL REQUIRED APPLICATION AND RETENTION PRIVILEGE CHECKS PASSED';
END $$;
