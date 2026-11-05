-- UTOP14 security-event retention privilege verification.
-- Run in the same database after provisioning. Review every row; a non-empty
-- unexpected membership or grant is a failure.

\echo 'Roles and attributes'
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolinherit
FROM pg_roles
WHERE rolname IN (
    'utop14_retention_owner',
    'utop14_retention_runner',
    'utop14_app'
)
ORDER BY rolname;

\echo 'Memberships involving retention roles (must be empty)'
SELECT member::regrole AS member, roleid::regrole AS granted_role
FROM pg_auth_members
WHERE roleid IN (
    'utop14_retention_owner'::regrole,
    'utop14_retention_runner'::regrole
);

\echo 'Application membership in retention roles (must be false)'
SELECT pg_has_role('utop14_app', 'utop14_retention_owner', 'member') AS app_is_owner_member,
       pg_has_role('utop14_app', 'utop14_retention_runner', 'member') AS app_is_runner_member;

\echo 'Function ownership and execute privileges'
SELECT p.oid::regprocedure AS function,
       p.proowner::regrole AS owner,
       p.prosecdef AS security_definer,
       p.proconfig AS function_settings,
       has_function_privilege(
           'utop14_retention_runner',
           p.oid,
           'EXECUTE'
       ) AS runner_can_execute,
       has_function_privilege(
           'utop14_app',
           p.oid,
           'EXECUTE'
       ) AS app_can_execute
FROM pg_proc AS p
WHERE p.oid = 'public.prune_security_events(text, timestamptz, integer, uuid, integer)'::regprocedure;

\echo 'Table privileges for retention roles and application'
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants
WHERE grantee IN ('utop14_retention_owner', 'utop14_retention_runner', 'utop14_app')
  AND table_name IN ('security_events', 'security_event_retention_holds',
                     'security_event_retention_runs')
ORDER BY grantee, table_name, privilege_type;

\echo 'Retention runner must not have direct dangerous privileges (all false)'
SELECT has_table_privilege('utop14_retention_runner', 'security_events', 'DELETE') AS runner_delete,
       has_table_privilege('utop14_retention_runner', 'security_events', 'UPDATE') AS runner_update,
       has_table_privilege('utop14_retention_runner', 'security_events', 'TRUNCATE') AS runner_truncate;

\echo 'Application must not have direct dangerous privileges (all false)'
SELECT has_table_privilege('utop14_app', 'security_events', 'DELETE') AS app_delete,
       has_table_privilege('utop14_app', 'security_events', 'UPDATE') AS app_update,
       has_table_privilege('utop14_app', 'security_events', 'TRUNCATE') AS app_truncate;

\echo 'Schema usage'
SELECT has_schema_privilege('utop14_retention_owner', 'public', 'USAGE') AS owner_usage,
       has_schema_privilege('utop14_retention_runner', 'public', 'USAGE') AS runner_usage;
