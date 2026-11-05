"""Disposable PostgreSQL ownership and hold-concurrency regression tests.

These tests are intentionally gated: set ``UTOP14_DISPOSABLE_PG=1`` to run
them.  They create a throwaway PostgreSQL cluster, run all migrations as a
dedicated schema owner, provision the retention roles as a superuser, and then
verify OPS-01 ownership separation plus the M14331-02 hold races.  They also
cover M14.3.14 column ACLs, database-level CREATE, MAINTAIN, verifier-role and
search_path checks.

They never touch the shared development database or production.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.extensions import db
from app.models import (
    Cart,
    CartItem,
    Category,
    Order,
    OrderItem,
    Payment,
    PaymentProof,
    Product,
    ProductImage,
    ProductReview,
    ProductVariant,
    SecurityEvent,
    User,
)
from app.models.security_event import SECURITY_EVENT_LOGIN_THROTTLED
from app.services.audit import (
    AdminAuditFilters,
    AuditContext,
    get_audit_log,
    list_audit_logs,
    record_audit_event,
)
from app.services.auth_rate_limit import (
    get_bucket,
    identifier_bucket_key,
    record_failure,
    reset_identifier_bucket,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("UTOP14_DISPOSABLE_PG") != "1",
    reason="set UTOP14_DISPOSABLE_PG=1 to run disposable PostgreSQL tests",
)

DB = "utop14_concurrency_test"


def _pg_bin() -> Path | None:
    pg_config = shutil.which("pg_config")
    if pg_config:
        result = subprocess.run(
            [pg_config, "--bindir"], capture_output=True, text=True, check=False
        )
        candidate = Path(result.stdout.strip())
        if result.returncode == 0 and (candidate / "initdb").exists():
            return candidate
    for candidate in sorted(Path("/usr/lib/postgresql").glob("*/bin/initdb")):
        return candidate.parent
    initdb = shutil.which("initdb")
    if initdb:
        return Path(initdb).parent
    return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {args}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def _psql(port: int, sql: str, *, db: str = DB) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            db,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _psql_as(port: int, role: str, sql: str, *, db: str = DB) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            role,
            "-d",
            db,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _role_dsn(port: int, role: str) -> str:
    return f"postgresql+psycopg://{role}@127.0.0.1:{port}/{DB}"


def _verify(port: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            "scripts/security_event_retention_verify.sql",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _verify_as(port: int, role: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            role,
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            "scripts/security_event_retention_verify.sql",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _verify_with_search_path(port: int, search_path: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PGOPTIONS"] = f"-c search_path={search_path}"
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            "scripts/security_event_retention_verify.sql",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _verify_with_temp_shadow(port: int) -> subprocess.CompletedProcess[str]:
    setup = (
        "CREATE TEMP TABLE pg_parameter_acl "
        "(parname text, paracl aclitem[]); "
        "CREATE TEMP TABLE pg_db_role_setting "
        "(setrole oid, setdatabase oid, setconfig text[]); "
        "CREATE FUNCTION pg_temp.has_parameter_privilege("
        "name, text, text) RETURNS boolean "
        "LANGUAGE sql AS 'SELECT false';"
    )
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            setup,
            "-f",
            "scripts/security_event_retention_verify.sql",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _verify_with_catalog_shadow(
    port: int,
    shadow_sql: str,
) -> subprocess.CompletedProcess[str]:
    """Run the complete verifier in a session pre-loaded with hostile objects.

    The setup statement executes before the verifier in the same psql session,
    so any temporary relation it creates shadows the same-named catalog for
    every unqualified reference.
    """
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            shadow_sql,
            "-f",
            "scripts/security_event_retention_verify.sql",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _psql_file_with_shadow(
    port: int,
    shadow_sql: str,
    path: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            shadow_sql,
            "-f",
            path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _psql_stdin_with_shadow(
    port: int,
    shadow_sql: str,
    sql: str,
) -> subprocess.CompletedProcess[str]:
    """Run ``sql`` in a session pre-loaded with ``shadow_sql``.

    psql ignores stdin when ``-c`` is given, so the setup and the script are
    concatenated into one stdin stream to keep them in the same session.
    """
    return _psql_stdin(port, shadow_sql + "\n" + sql)


def _psql_file(port: int, path: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _psql_stdin(port: int, sql: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "psql",
            "-h",
            "127.0.0.1",
            "-p",
            str(port),
            "-U",
            "postgres",
            "-d",
            DB,
            "-v",
            "ON_ERROR_STOP=1",
        ],
        input=sql,
        capture_output=True,
        text=True,
        check=False,
    )


def _acl_snapshot(engine) -> list[tuple[str, str, str, str]]:
    """Canonical ACL snapshot (grantees/privileges, not grantor OIDs)."""

    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT 'table' AS kind,
                       c.relname AS object_name,
                       CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                            ELSE pg_get_userbyid(a.grantee) END AS grantee,
                       a.privilege_type
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(
                        c.relacl,
                        acldefault(
                            CASE WHEN c.relkind = 'S' THEN 's'::"char"
                                 ELSE 'r'::"char" END,
                            c.relowner
                        )
                    )
                ) a
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'f', 'S')
                  AND a.grantee <> c.relowner
                UNION ALL
                SELECT 'function',
                       p.proname || '(' ||
                       pg_get_function_identity_arguments(p.oid) || ')',
                       CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                            ELSE pg_get_userbyid(a.grantee) END,
                       a.privilege_type
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(p.proacl, acldefault('f'::"char", p.proowner))
                ) a
                WHERE n.nspname = 'public'
                  AND a.grantee <> p.proowner
                ORDER BY 1, 2, 3, 4
                """
            )
        ).all()
    return [tuple(row) for row in rows]


def _owner_snapshot(engine) -> list[tuple[str, str, str]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT 'relation', c.relname, pg_get_userbyid(c.relowner)
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public'
                  AND c.relkind IN ('r', 'p', 'f', 'S')
                UNION ALL
                SELECT 'function',
                       p.proname || '(' ||
                       pg_get_function_identity_arguments(p.oid) || ')',
                       pg_get_userbyid(p.proowner)
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'public'
                ORDER BY 1, 2, 3
                """
            )
        ).all()
    return [tuple(row) for row in rows]


def _assert_verify_fails(port: int, *needles: str) -> str:
    result = _verify(port)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    for needle in needles:
        assert needle in output, output
    return output


def _insert_event(
    engine, *, event_type: str, outcome: str, reason: str, created_at: datetime
) -> int:
    with engine.begin() as conn:
        return conn.execute(
            text(
                "INSERT INTO security_events "
                "(event_type, outcome, reason_code, ip_address, user_agent, "
                "metadata, created_at) "
                "VALUES (:event_type, :outcome, :reason, '127.0.0.1', '', "
                "'{}'::jsonb, :created_at) RETURNING id"
            ),
            {
                "event_type": event_type,
                "outcome": outcome,
                "reason": reason,
                "created_at": created_at,
            },
        ).scalar_one()


def _prune(engine, *, scope: str, cutoff: datetime, batch: int = 100) -> int:
    with engine.begin() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT public.prune_security_events("
                    ":scope, :cutoff, :batch, CAST(:run_id AS uuid), 0)"
                ),
                {
                    "scope": scope,
                    "cutoff": cutoff,
                    "batch": batch,
                    "run_id": str(uuid.uuid4()),
                },
            ).scalar_one()
        )


def test_disposable_ownership_and_hold_concurrency() -> None:
    pg_bin = _pg_bin()
    if pg_bin is None:
        pytest.skip("PostgreSQL server binaries are not available")

    port = _free_port()
    data_dir = Path(tempfile.mkdtemp(prefix="utop14-retention-pg-"))
    try:
        _run(str(pg_bin / "initdb"), "-D", str(data_dir), "-U", "postgres", "--auth=trust")
        _run(
            str(pg_bin / "pg_ctl"),
            "-D",
            str(data_dir),
            "-o",
            f"-p {port} -h 127.0.0.1 -k /tmp",
            "-l",
            str(data_dir / "postgres.log"),
            "start",
        )

        admin_dsn = f"postgresql+psycopg://postgres@127.0.0.1:{port}/postgres"
        admin = create_engine(admin_dsn, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            conn.execute(
                text(
                    "CREATE ROLE utop14_schema_owner LOGIN NOSUPERUSER "
                    "NOCREATEDB NOCREATEROLE NOINHERIT"
                )
            )
            conn.execute(
                text("CREATE ROLE utop14_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
            )
            conn.execute(text(f"CREATE DATABASE {DB} OWNER utop14_schema_owner"))
        admin.dispose()

        schema_owner_dsn = _role_dsn(port, "utop14_schema_owner")
        app = create_app(
            "testing",
            {
                "SQLALCHEMY_DATABASE_URI": schema_owner_dsn,
                "SECURITY_EVENT_HASH_KEY": "concurrency-test-key-0123456789abcdef",
                "SECURITY_EVENT_RETENTION_DATABASE_URL": _role_dsn(port, "utop14_retention_runner"),
            },
        )
        alembic_config = Config("migrations/alembic.ini")
        alembic_config.set_main_option("script_location", "migrations")
        with app.app_context():
            command.upgrade(alembic_config, "head")
            db.engine.dispose()

        ownership_sql = (
            Path("scripts/security_event_retention_ownership_template.sql")
            .read_text()
            .replace("<schema_owner>", "utop14_schema_owner")
            .replace("<database_name>", DB)
        )
        ownership = subprocess.run(
            [
                "psql",
                "-h",
                "127.0.0.1",
                "-p",
                str(port),
                "-U",
                "postgres",
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
            ],
            input=ownership_sql,
            capture_output=True,
            text=True,
            check=False,
        )
        assert ownership.returncode == 0, ownership.stderr

        provisioning = subprocess.run(
            [
                "psql",
                "-h",
                "127.0.0.1",
                "-p",
                str(port),
                "-U",
                "postgres",
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "scripts/security_event_retention_roles.sql",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert provisioning.returncode == 0, provisioning.stderr

        verification = subprocess.run(
            [
                "psql",
                "-h",
                "127.0.0.1",
                "-p",
                str(port),
                "-U",
                "postgres",
                "-d",
                DB,
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "scripts/security_event_retention_verify.sql",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert verification.returncode == 0, verification.stdout + verification.stderr
        combined_verification = verification.stdout + verification.stderr
        assert (
            "ALL REQUIRED APPLICATION AND RETENTION PRIVILEGE CHECKS PASSED"
            in combined_verification
        )

        admin = create_engine(f"postgresql+psycopg://postgres@127.0.0.1:{port}/{DB}")
        schema_owner = create_engine(schema_owner_dsn)
        app_engine = create_engine(_role_dsn(port, "utop14_app"))
        runner = create_engine(_role_dsn(port, "utop14_retention_runner"))

        # --- M14312-03: repeatable provisioning and identical state --------
        acl_before = _acl_snapshot(admin)
        owners_before = _owner_snapshot(admin)
        second_ownership = _psql_stdin(port, ownership_sql)
        assert second_ownership.returncode == 0, second_ownership.stdout + second_ownership.stderr
        second_provisioning = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert second_provisioning.returncode == 0, (
            second_provisioning.stdout + second_provisioning.stderr
        )
        assert "ROLE PROVISIONING COMMITTED SUCCESSFULLY" in (
            second_provisioning.stdout + second_provisioning.stderr
        )
        assert _acl_snapshot(admin) == acl_before, "provisioning changed ACL state"
        assert _owner_snapshot(admin) == owners_before, "provisioning changed owners"
        assert _verify(port).returncode == 0

        # --- M14311-04: hold-lock trigger EXECUTE is unnecessary ------------
        with admin.connect() as conn:
            app_hold_exec = conn.execute(
                text(
                    "SELECT has_function_privilege('utop14_app', "
                    "'public.security_event_retention_holds_lock()', 'EXECUTE')"
                )
            ).scalar_one()
            app_prune_exec = conn.execute(
                text(
                    "SELECT has_function_privilege('utop14_app', "
                    "'public.prune_security_events(text, timestamptz, integer, uuid, integer)', "
                    "'EXECUTE')"
                )
            ).scalar_one()
            public_hold_exec = conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc p, "
                    "aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
                    "WHERE p.oid = "
                    "'public.security_event_retention_holds_lock()'::regprocedure "
                    "AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'"
                )
            ).scalar_one()
        assert app_hold_exec is False, "app still has hold-lock EXECUTE"
        assert app_prune_exec is False, "app has retention function EXECUTE"
        assert public_hold_exec == 0, "PUBLIC has hold-lock EXECUTE"

        hold_event = _insert_event(
            schema_owner,
            event_type="auth.login_failed",
            outcome="failure",
            reason="invalid_password",
            created_at=datetime.now(UTC) - timedelta(days=120),
        )
        # INSERT and UPDATE must still fire the trigger without app EXECUTE.
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'no-exec-insert', 'op', now() + interval '1 day')"
                ),
                {"id": hold_event},
            )
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE security_event_retention_holds SET reason='no-exec-update' "
                    "WHERE security_event_id=:id"
                ),
                {"id": hold_event},
            )
        # Direct invocation of a trigger function must fail for the app.
        try:
            with app_engine.begin() as conn:
                conn.execute(text("SELECT public.security_event_retention_holds_lock()"))
            raise AssertionError("app directly invoked the hold-lock trigger function")
        except SQLAlchemyError:
            pass
        with schema_owner.begin() as conn:
            conn.execute(
                text("DELETE FROM security_event_retention_holds WHERE security_event_id=:id"),
                {"id": hold_event},
            )
        app_role = create_app(
            "testing",
            {
                "SQLALCHEMY_DATABASE_URI": _role_dsn(port, "utop14_app"),
                "SECURITY_EVENT_HASH_KEY": ("app-role-key-0123456789abcdef0123456789"),
                "AUTH_RATE_LIMIT_ENABLED": True,
                "AUTH_RATE_LIMIT_WINDOW_SECONDS": 900,
                "AUTH_RATE_LIMIT_IDENTIFIER_MAX_FAILURES": 5,
                "AUTH_RATE_LIMIT_IDENTIFIER_THRESHOLDS": (5,),
                "AUTH_RATE_LIMIT_IDENTIFIER_COOLDOWNS": (60,),
                "AUTH_RATE_LIMIT_IP_MAX_FAILURES": 30,
                "AUTH_RATE_LIMIT_IP_THRESHOLDS": (30,),
                "AUTH_RATE_LIMIT_IP_COOLDOWNS": (60,),
                "AUTH_RATE_LIMIT_COMBINED_MAX_FAILURES": 10,
                "AUTH_RATE_LIMIT_COMBINED_THRESHOLDS": (10,),
                "AUTH_RATE_LIMIT_COMBINED_COOLDOWNS": (60,),
            },
        )
        app_role.config["WTF_CSRF_ENABLED"] = False
        now = datetime.now(UTC)

        # --- OPS-01 ownership and direct privilege probes -----------------
        with admin.connect() as conn:
            owners = dict(
                conn.execute(
                    text(
                        "SELECT tablename, tableowner FROM pg_tables "
                        "WHERE schemaname='public' AND tablename IN "
                        "('security_events','security_event_retention_holds',"
                        "'security_event_retention_runs')"
                    )
                ).all()
            )
            assert set(owners.values()) == {"utop14_schema_owner"}, owners
            function_owner = conn.execute(
                text(
                    "SELECT pg_get_userbyid(p.proowner) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid=p.pronamespace "
                    "WHERE n.nspname='public' AND p.proname='prune_security_events'"
                )
            ).scalar_one()
            assert function_owner == "utop14_retention_owner", function_owner
            trigger_owner = conn.execute(
                text(
                    "SELECT pg_get_userbyid(p.proowner) FROM pg_proc p "
                    "JOIN pg_namespace n ON n.oid=p.pronamespace "
                    "WHERE n.nspname='public' "
                    "AND p.proname='security_event_retention_holds_lock'"
                )
            ).scalar_one()
            assert trigger_owner == "utop14_schema_owner", trigger_owner

        for statement in (
            "ALTER TABLE public.security_events DISABLE TRIGGER security_events_append_only",
            "ALTER TABLE public.security_events ADD COLUMN probe integer",
            "TRUNCATE public.security_events",
            "DELETE FROM public.security_events WHERE false",
            "UPDATE public.security_events SET user_agent=user_agent WHERE false",
            "SELECT public.prune_security_events('success_logout', "
            "now() - interval '100 days', 10, "
            "'00000000-0000-0000-0000-000000000000'::uuid, 0)",
        ):
            try:
                with app_engine.begin() as conn:
                    conn.execute(text(statement))
                raise AssertionError(f"app unexpectedly executed: {statement}")
            except SQLAlchemyError:
                pass

        for target in (
            "utop14_schema_owner",
            "utop14_retention_owner",
            "utop14_retention_runner",
        ):
            try:
                with app_engine.begin() as conn:
                    conn.execute(text(f"SET LOCAL ROLE {target}"))
                raise AssertionError(f"app unexpectedly SET ROLE {target}")
            except SQLAlchemyError:
                pass

        try:
            with runner.begin() as conn:
                conn.execute(text("DELETE FROM security_events WHERE false"))
            raise AssertionError("runner unexpectedly deleted events")
        except SQLAlchemyError:
            pass

        # --- RR-01: actual app INSERT with sequence privileges ------------
        app_insert = (
            "INSERT INTO security_events "
            "(event_type, outcome, reason_code, ip_address, user_agent, metadata) "
            "VALUES ('auth.logout', 'success', 'user_requested', "
            "'127.0.0.1', '', '{}'::jsonb) RETURNING id"
        )
        with app_engine.begin() as conn:
            first_id = conn.execute(text(app_insert)).scalar_one()
            second_id = conn.execute(text(app_insert)).scalar_one()
        assert second_id > first_id > 0, (first_id, second_id)
        with admin.connect() as conn:
            persisted = conn.execute(
                text("SELECT count(*) FROM security_events WHERE id IN (:a,:b)"),
                {"a": first_id, "b": second_id},
            ).scalar_one()
            after_last = conn.execute(
                text("SELECT last_value FROM security_events_id_seq")
            ).scalar_one()
        assert persisted == 2, persisted
        assert after_last >= second_id, (after_last, second_id)

        # The app must not own or alter the sequence.
        for statement in (
            "ALTER SEQUENCE security_events_id_seq OWNER TO utop14_app",
            "ALTER SEQUENCE security_events_id_seq RESTART WITH 1",
            "DROP SEQUENCE security_events_id_seq",
        ):
            try:
                with app_engine.begin() as conn:
                    conn.execute(text(statement))
                raise AssertionError(f"app unexpectedly executed: {statement}")
            except SQLAlchemyError:
                pass

        # Negative verification: revoke USAGE, prove FAIL and actual INSERT failure.
        with admin.begin() as conn:
            conn.execute(text("REVOKE USAGE ON SEQUENCE security_events_id_seq FROM utop14_app"))
        revoked = _verify(port)
        revoked_output = revoked.stdout + revoked.stderr
        assert revoked.returncode != 0, revoked_output
        assert "security_events_id_seq" in revoked_output, revoked_output
        try:
            with app_engine.begin() as conn:
                conn.execute(text(app_insert))
            raise AssertionError("app insert succeeded without sequence USAGE")
        except SQLAlchemyError:
            pass
        with admin.begin() as conn:
            conn.execute(
                text("GRANT USAGE, SELECT ON SEQUENCE security_events_id_seq TO utop14_app")
            )
        assert _verify(port).returncode == 0

        # --- RR-02: SET-only owner membership must fail verification -------
        set_grant = _psql(
            port,
            "GRANT utop14_schema_owner TO utop14_app WITH SET TRUE, INHERIT FALSE",
        )
        assert set_grant.returncode == 0, set_grant.stderr
        set_ok = False
        conn = app_engine.connect()
        trans = conn.begin()
        try:
            conn.execute(text("SET LOCAL ROLE utop14_schema_owner"))
            conn.execute(
                text(
                    "ALTER TABLE public.security_events DISABLE TRIGGER security_events_append_only"
                )
            )
            set_ok = True
        except SQLAlchemyError:
            set_ok = False
        finally:
            trans.rollback()
            conn.close()
        assert set_ok is True, "app could not SET ROLE to schema owner"
        set_verify = _verify(port)
        set_output = set_verify.stdout + set_verify.stderr
        assert set_verify.returncode != 0, set_output
        assert (
            "owner role" in set_output or "SET/USAGE" in set_output or "membership" in set_output
        ), set_output
        revoke = _psql(port, "REVOKE utop14_schema_owner FROM utop14_app")
        assert revoke.returncode == 0, revoke.stderr
        assert _verify(port).returncode == 0

        # --- RR-02: transitive SET-only membership must fail verification --
        for statement in (
            "CREATE ROLE utop14_membership_bridge NOLOGIN",
            "GRANT utop14_schema_owner TO utop14_membership_bridge WITH SET TRUE, INHERIT FALSE",
            "GRANT utop14_membership_bridge TO utop14_app WITH SET TRUE, INHERIT FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        transitive = _verify(port)
        transitive_output = transitive.stdout + transitive.stderr
        assert transitive.returncode != 0, transitive_output
        assert (
            "owner role" in transitive_output
            or "SET/USAGE" in transitive_output
            or "membership" in transitive_output
        ), transitive_output
        for statement in (
            "REVOKE utop14_membership_bridge FROM utop14_app",
            "REVOKE utop14_schema_owner FROM utop14_membership_bridge",
            "DROP ROLE utop14_membership_bridge",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # --- M14314-06: application role search_path -----------------------
        search_engine = create_engine(_role_dsn(port, "utop14_app"))
        with search_engine.connect() as conn:
            assert conn.execute(text("SHOW search_path")).scalar_one() == "public, pg_catalog"
        search_engine.dispose()

        result = _psql(
            port,
            f"ALTER ROLE utop14_app IN DATABASE {DB} SET search_path = pg_catalog, public",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "search_path", "utop14_app")
        result = _psql(
            port,
            f"ALTER ROLE utop14_app IN DATABASE {DB} RESET search_path",
        )
        assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # --- M14314-04: verification requires an actual superuser ---------
        schema_verify = _verify_as(port, "utop14_schema_owner")
        schema_output = schema_verify.stdout + schema_verify.stderr
        assert schema_verify.returncode != 0, schema_output
        assert "superuser" in schema_output.lower(), schema_output
        result = _psql(
            port,
            "CREATE ROLE m14314_verifier LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
        )
        assert result.returncode == 0, result.stderr
        ordinary_verify = _verify_as(port, "m14314_verifier")
        ordinary_output = ordinary_verify.stdout + ordinary_verify.stderr
        assert ordinary_verify.returncode != 0, ordinary_output
        assert "superuser" in ordinary_output.lower(), ordinary_output
        assert _psql(port, "DROP ROLE m14314_verifier").returncode == 0

        # --- M14311-01: default-deny predefined/custom/nested memberships ---
        # Direct predefined role with SET-only membership.
        result = _psql(
            port,
            "GRANT pg_write_all_data TO utop14_app WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "pg_write_all_data", "membership")
        with app_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE pg_write_all_data"))
            conn.execute(text("DELETE FROM security_event_retention_holds WHERE false"))
            conn.execute(text("DELETE FROM auth_rate_limits WHERE false"))
        assert _psql(port, "REVOKE pg_write_all_data FROM utop14_app").returncode == 0
        assert _verify(port).returncode == 0

        # Direct pg_read_all_data SET-only membership grants the run log.
        result = _psql(
            port,
            "GRANT pg_read_all_data TO utop14_app WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "pg_read_all_data", "membership")
        with app_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE pg_read_all_data"))
            conn.execute(text("SELECT count(*) FROM security_event_retention_runs")).scalar_one()
        assert _psql(port, "REVOKE pg_read_all_data FROM utop14_app").returncode == 0
        assert _verify(port).returncode == 0

        # Custom SET-only role with SELECT on the retention run log.
        for statement in (
            "CREATE ROLE m14312_reader NOLOGIN",
            "GRANT SELECT ON public.security_event_retention_runs TO m14312_reader",
            "GRANT m14312_reader TO utop14_app WITH SET TRUE, INHERIT FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_reader", "membership")
        with app_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE m14312_reader"))
            conn.execute(text("SELECT count(*) FROM security_event_retention_runs")).scalar_one()
        for statement in (
            "REVOKE m14312_reader FROM utop14_app",
            "REVOKE SELECT ON public.security_event_retention_runs FROM m14312_reader",
            "DROP ROLE m14312_reader",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # Custom SET-only role with DELETE on retention holds.
        for statement in (
            "CREATE ROLE m14312_hold_deleter NOLOGIN",
            "GRANT DELETE ON public.security_event_retention_holds TO m14312_hold_deleter",
            "GRANT m14312_hold_deleter TO utop14_app WITH SET TRUE, INHERIT FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_hold_deleter", "membership")
        with app_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE m14312_hold_deleter"))
            conn.execute(text("DELETE FROM security_event_retention_holds WHERE false"))
        for statement in (
            "REVOKE m14312_hold_deleter FROM utop14_app",
            "REVOKE DELETE ON public.security_event_retention_holds FROM m14312_hold_deleter",
            "DROP ROLE m14312_hold_deleter",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # Nested/transitive membership: app -> bridge -> nested -> predefined.
        for statement in (
            "CREATE ROLE m14312_bridge NOLOGIN",
            "CREATE ROLE m14312_nested NOLOGIN",
            "GRANT pg_write_all_data TO m14312_nested WITH SET TRUE, INHERIT FALSE",
            "GRANT m14312_nested TO m14312_bridge WITH SET TRUE, INHERIT FALSE",
            "GRANT m14312_bridge TO utop14_app WITH SET TRUE, INHERIT FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_bridge", "m14312_nested", "pg_write_all_data")
        with app_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE m14312_bridge"))
            conn.execute(text("SET LOCAL ROLE m14312_nested"))
            conn.execute(text("SET LOCAL ROLE pg_write_all_data"))
            conn.execute(text("DELETE FROM security_event_retention_holds WHERE false"))
        for statement in (
            "REVOKE m14312_bridge FROM utop14_app",
            "REVOKE m14312_nested FROM m14312_bridge",
            "REVOKE pg_write_all_data FROM m14312_nested",
            "DROP ROLE m14312_bridge",
            "DROP ROLE m14312_nested",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # INHERIT-only membership is forbidden even when SET is disabled.
        for statement in (
            "CREATE ROLE m14312_inherit_reader NOLOGIN",
            "GRANT SELECT ON public.security_event_retention_runs TO m14312_inherit_reader",
            "GRANT m14312_inherit_reader TO utop14_app WITH INHERIT TRUE, SET FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_inherit_reader", "inherit=true")
        try:
            with app_engine.begin() as conn:
                conn.execute(text("SET LOCAL ROLE m14312_inherit_reader"))
            raise AssertionError("app SET ROLE to an INHERIT-only membership")
        except SQLAlchemyError:
            pass
        for statement in (
            "REVOKE m14312_inherit_reader FROM utop14_app",
            "REVOKE SELECT ON public.security_event_retention_runs FROM m14312_inherit_reader",
            "DROP ROLE m14312_inherit_reader",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # ADMIN option is forbidden even when the membership is not used.
        for statement in (
            "CREATE ROLE m14312_admin_role NOLOGIN",
            "GRANT m14312_admin_role TO utop14_app WITH ADMIN TRUE, INHERIT FALSE, SET TRUE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_admin_role", "admin=true")
        for statement in (
            "REVOKE m14312_admin_role FROM utop14_app",
            "DROP ROLE m14312_admin_role",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # The retention roles are subject to the same default-deny rule.
        result = _psql(
            port,
            "GRANT pg_read_all_data TO utop14_retention_owner WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "utop14_retention_owner", "pg_read_all_data")
        assert (
            _psql(
                port,
                "REVOKE pg_read_all_data FROM utop14_retention_owner",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "GRANT pg_write_all_data TO utop14_retention_runner WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "utop14_retention_runner", "pg_write_all_data")
        assert (
            _psql(
                port,
                "REVOKE pg_write_all_data FROM utop14_retention_runner",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        # Reverse membership: another role can assume utop14_app.
        for statement in (
            "CREATE ROLE m14312_reverse NOLOGIN",
            "GRANT utop14_app TO m14312_reverse",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "reverse membership", "m14312_reverse")
        for statement in (
            "REVOKE utop14_app FROM m14312_reverse",
            "DROP ROLE m14312_reverse",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # --- Actual app-role rate limiting, audit, and application writes ---
        with app_role.app_context():
            rate_key = identifier_bucket_key("ratelimit@example.com")
            state = record_failure("identifier", rate_key)
            assert state.failure_count == 1
            fetched = get_bucket("identifier", rate_key)
            assert fetched is not None and fetched.failure_count == 1
            assert reset_identifier_bucket("ratelimit@example.com") == 1
            assert get_bucket("identifier", rate_key) is None

            throttle_user = User(
                email="throttle@example.com",
                full_name="Throttle",
                role="customer",
                is_active=True,
            )
            throttle_user.set_password("CorrectPass123")
            db.session.add(throttle_user)
            db.session.commit()

            client = app_role.test_client()
            for _ in range(5):
                response = client.post(
                    "/auth/login",
                    data={
                        "email": "throttle@example.com",
                        "password": "WrongPass123",
                    },
                )
                assert response.status_code == 200, response.status_code
            throttled = client.post(
                "/auth/login",
                data={
                    "email": "throttle@example.com",
                    "password": "WrongPass123",
                },
            )
            assert throttled.status_code == 429, throttled.status_code
            assert throttled.headers.get("Retry-After")
            throttle_events = db.session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == SECURITY_EVENT_LOGIN_THROTTLED
                )
            ).all()
            assert throttle_events
            throttle_event_id = throttle_events[0].id

            actor = User(
                email="audit-actor@example.com",
                full_name="Audit Actor",
                role="admin",
                is_active=True,
            )
            actor.set_password("CorrectPass123")
            target = User(
                email="audit-target@example.com",
                full_name="Audit Target",
                role="customer",
                is_active=True,
            )
            target.set_password("CorrectPass123")
            db.session.add_all([actor, target])
            db.session.commit()
            audit_context = AuditContext(
                actor_id=actor.id,
                actor_email=actor.email,
                ip_address="127.0.0.1",
                user_agent="",
                request_id=None,
            )
            audit = record_audit_event(
                db.session,
                context=audit_context,
                target=target,
                action="user.activated",
                before_data={"is_active": False},
                after_data={"is_active": True},
            )
            db.session.commit()
            assert audit.id is not None
            audit_id = audit.id
            audit_page = list_audit_logs(AdminAuditFilters())
            assert audit_page.total >= 1
            assert get_audit_log(audit.id) is not None

            category = Category(
                name="Review Category",
                slug="review-category",
                description="",
                icon="images/review-icon.png",
                position=0,
                is_active=True,
            )
            db.session.add(category)
            db.session.commit()
            product = Product(
                category_id=category.id,
                name="Review Product",
                slug="review-product",
                description="",
                price=Decimal("10.00"),
                image_path="images/review-product.png",
                image_alt="",
                is_active=True,
            )
            db.session.add(product)
            db.session.commit()
            variant = ProductVariant(
                product_id=product.id,
                size="M",
                color="Black",
                sku="REVIEW-M-BLACK",
                stock=10,
                is_active=True,
            )
            db.session.add(variant)
            db.session.commit()
            image = ProductImage(
                product_id=product.id,
                image_path="images/review-product-2.png",
                alt_text="",
                position=1,
            )
            db.session.add(image)
            db.session.commit()
            image.alt_text = "Updated"
            db.session.commit()
            db.session.delete(image)
            db.session.commit()

            cart = Cart(user_id=throttle_user.id)
            db.session.add(cart)
            db.session.commit()
            cart_item = CartItem(cart_id=cart.id, variant_id=variant.id, quantity=1)
            db.session.add(cart_item)
            db.session.commit()
            cart_item.quantity = 2
            db.session.commit()
            db.session.delete(cart_item)
            db.session.commit()

            order = Order(
                order_number="REVIEW-ORDER-1",
                user_id=throttle_user.id,
                status="pending",
                payment_status="unpaid",
                recipient_name="Review",
                recipient_phone="1",
                shipping_address="Address",
                shipping_city="City",
                shipping_postal_code="1",
                subtotal=Decimal("10.00"),
                shipping_cost=Decimal("0.00"),
                total=Decimal("10.00"),
            )
            db.session.add(order)
            db.session.commit()
            order.status = "processing"
            db.session.commit()
            order_item = OrderItem(
                order_id=order.id,
                product_id=product.id,
                variant_id=variant.id,
                product_name=product.name,
                sku=variant.sku,
                size=variant.size,
                color=variant.color,
                unit_price=Decimal("10.00"),
                quantity=1,
                line_total=Decimal("10.00"),
            )
            db.session.add(order_item)
            db.session.commit()
            payment = Payment(
                payment_reference="REVIEW-PAY-1",
                order_id=order.id,
                provider="manual_transfer",
                payment_method="bank_transfer",
                amount=Decimal("10.00"),
                currency="IDR",
                status="pending",
                idempotency_key="review-pay-1",
                expires_at=now + timedelta(hours=1),
            )
            db.session.add(payment)
            db.session.commit()
            payment.status = "failed"
            db.session.commit()
            proof = PaymentProof(
                payment_id=payment.id,
                proof_filename="review-proof.jpg",
                mime_type="image/jpeg",
                file_size=1,
                status="pending_review",
                submitted_at=now,
            )
            db.session.add(proof)
            db.session.commit()
            proof.status = "approved"
            db.session.commit()
            review = ProductReview(
                product_id=product.id,
                user_id=throttle_user.id,
                order_item_id=order_item.id,
                rating=5,
                comment="Review comment",
                status="published",
            )
            db.session.add(review)
            db.session.commit()
            review.status = "hidden"
            review.moderation_reason = "test"
            db.session.commit()

        # Denied app mutations on protected/append-only tables.
        for statement in (
            "UPDATE audit_logs SET actor_email='changed@example.com' WHERE false",
            "DELETE FROM audit_logs WHERE false",
            "TRUNCATE audit_logs",
            "ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only",
            "UPDATE security_events SET user_agent='changed' WHERE false",
            "DELETE FROM security_events WHERE false",
            "TRUNCATE security_events",
            "ALTER TABLE security_events DISABLE TRIGGER security_events_append_only",
            "DELETE FROM users WHERE false",
        ):
            try:
                with app_engine.begin() as conn:
                    conn.execute(text(statement))
                raise AssertionError(f"app unexpectedly executed: {statement}")
            except SQLAlchemyError:
                pass

        # Negative verification: revoke required app privileges one at a time.
        negative_grants = (
            (
                "REVOKE INSERT ON auth_rate_limits FROM utop14_app",
                "GRANT INSERT ON auth_rate_limits TO utop14_app",
                "auth_rate_limits",
            ),
            (
                "REVOKE DELETE ON auth_rate_limits FROM utop14_app",
                "GRANT DELETE ON auth_rate_limits TO utop14_app",
                "auth_rate_limits",
            ),
            (
                "REVOKE INSERT ON audit_logs FROM utop14_app",
                "GRANT INSERT ON audit_logs TO utop14_app",
                "audit_logs",
            ),
            (
                "REVOKE SELECT ON audit_logs FROM utop14_app",
                "GRANT SELECT ON audit_logs TO utop14_app",
                "audit_logs",
            ),
            (
                "REVOKE USAGE ON SEQUENCE audit_logs_id_seq FROM utop14_app",
                "GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO utop14_app",
                "audit_logs_id_seq",
            ),
        )
        for revoke_sql, restore_sql, needle in negative_grants:
            revoked = _psql(port, revoke_sql)
            assert revoked.returncode == 0, revoked.stderr
            failed = _verify(port)
            failed_output = failed.stdout + failed.stderr
            assert failed.returncode != 0, failed_output
            assert needle in failed_output, failed_output
            restored = _psql(port, restore_sql)
            assert restored.returncode == 0, restored.stderr
            assert _verify(port).returncode == 0

        transferred = _psql(port, "ALTER TABLE public.audit_logs OWNER TO utop14_app")
        assert transferred.returncode == 0, transferred.stderr
        ownership_failed = _verify(port)
        ownership_output = ownership_failed.stdout + ownership_failed.stderr
        assert ownership_failed.returncode != 0, ownership_output
        assert "audit_logs" in ownership_output or "owner" in ownership_output
        restored_owner = _psql(
            port,
            "ALTER TABLE public.audit_logs OWNER TO utop14_schema_owner",
        )
        assert restored_owner.returncode == 0, restored_owner.stderr
        regranted_table = _psql(
            port,
            "GRANT SELECT, INSERT ON public.audit_logs TO utop14_app",
        )
        assert regranted_table.returncode == 0, regranted_table.stderr
        regranted_sequence = _psql(
            port,
            "GRANT USAGE, SELECT ON SEQUENCE public.audit_logs_id_seq TO utop14_app",
        )
        assert regranted_sequence.returncode == 0, regranted_sequence.stderr
        assert _verify(port).returncode == 0

        # --- M14311-02: schema-wide privilege and object inventory ----------
        # An unexpected non-system schema must fail even without grants.
        result = _psql(port, "CREATE SCHEMA m14312_unexpected_schema")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_unexpected_schema", "schemas")
        assert _psql(port, "DROP SCHEMA m14312_unexpected_schema").returncode == 0
        assert _verify(port).returncode == 0

        # App USAGE/CREATE on a non-public schema must fail and is exploitable.
        for statement in (
            "CREATE SCHEMA m14312_app_schema",
            "GRANT USAGE, CREATE ON SCHEMA m14312_app_schema TO utop14_app",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_app_schema")
        with app_engine.begin() as conn:
            conn.execute(text("CREATE TABLE m14312_app_schema.m14312_probe (id integer)"))
        assert _psql(port, "DROP SCHEMA m14312_app_schema CASCADE").returncode == 0
        assert _verify(port).returncode == 0

        # CREATE through PUBLIC is an effective app privilege and must fail.
        result = _psql(port, "GRANT CREATE ON SCHEMA public TO PUBLIC")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "CREATE on schema public")
        assert _psql(port, "REVOKE CREATE ON SCHEMA public FROM PUBLIC").returncode == 0
        assert _verify(port).returncode == 0

        # CREATE through a custom role is a forbidden membership path.
        for statement in (
            "CREATE ROLE m14312_schema_creator NOLOGIN",
            "GRANT CREATE ON SCHEMA public TO m14312_schema_creator",
            "GRANT m14312_schema_creator TO utop14_app WITH SET TRUE, INHERIT FALSE",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_schema_creator", "membership")
        for statement in (
            "REVOKE m14312_schema_creator FROM utop14_app",
            "REVOKE CREATE ON SCHEMA public FROM m14312_schema_creator",
            "DROP ROLE m14312_schema_creator",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # An unexpected user-defined domain/type must fail closed.
        result = _psql(port, "CREATE DOMAIN public.m14312_review_domain AS text")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_review_domain")
        assert _psql(port, "DROP DOMAIN public.m14312_review_domain").returncode == 0
        assert _verify(port).returncode == 0

        result = _psql(port, "CREATE TYPE public.m14312_review_enum AS ENUM ('a', 'b')")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14312_review_enum")
        assert _psql(port, "DROP TYPE public.m14312_review_enum").returncode == 0
        assert _verify(port).returncode == 0

        # --- M14311-05: complete function EXECUTE matrix --------------------
        function_cases = (
            (
                "GRANT EXECUTE ON FUNCTION public.audit_logs_reject_mutation() "
                "TO utop14_retention_runner",
                "REVOKE EXECUTE ON FUNCTION public.audit_logs_reject_mutation() "
                "FROM utop14_retention_runner",
                "audit_logs_reject_mutation",
            ),
            (
                "GRANT EXECUTE ON FUNCTION public.security_events_reject_mutation() "
                "TO utop14_retention_owner",
                "REVOKE EXECUTE ON FUNCTION public.security_events_reject_mutation() "
                "FROM utop14_retention_owner",
                "security_events_reject_mutation",
            ),
            (
                "GRANT EXECUTE ON FUNCTION "
                "public.security_event_retention_holds_lock() TO utop14_app",
                "REVOKE EXECUTE ON FUNCTION "
                "public.security_event_retention_holds_lock() FROM utop14_app",
                "security_event_retention_holds_lock",
            ),
            (
                "GRANT EXECUTE ON FUNCTION public.audit_logs_reject_mutation() TO utop14_app",
                "REVOKE EXECUTE ON FUNCTION public.audit_logs_reject_mutation() FROM utop14_app",
                "audit_logs_reject_mutation",
            ),
            (
                "GRANT EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) FROM PUBLIC",
                "prune_security_events",
            ),
            (
                "GRANT EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) TO utop14_app",
                "REVOKE EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) FROM utop14_app",
                "prune_security_events",
            ),
            (
                "GRANT EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) "
                "TO utop14_schema_owner",
                "REVOKE EXECUTE ON FUNCTION public.prune_security_events("
                "text, timestamptz, integer, uuid, integer) "
                "FROM utop14_schema_owner",
                "prune_security_events",
            ),
        )
        for grant_sql, revoke_sql, needle in function_cases:
            result = _psql(port, grant_sql)
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, needle)
            result = _psql(port, revoke_sql)
            assert result.returncode == 0, result.stderr
            assert _verify(port).returncode == 0

        # --- M14313-01: column-level ACLs are forbidden ---------------------
        with admin.begin() as conn:
            column_user_id = conn.execute(
                text(
                    "INSERT INTO users "
                    "(email, password_hash, full_name, role, is_active) "
                    "VALUES ('m14314-audit@example.com', 'x', 'M14314', "
                    "'customer', true) RETURNING id"
                )
            ).scalar_one()
            column_audit_id = conn.execute(
                text(
                    "INSERT INTO audit_logs "
                    "(actor_id, actor_email, target_email, action, before_data, "
                    "after_data, ip_address, user_agent) "
                    "VALUES (:uid, 'actor@example.com', 'target@example.com', "
                    "'user.activated', '{}'::jsonb, '{}'::jsonb, "
                    "'127.0.0.1', '') RETURNING id"
                ),
                {"uid": column_user_id},
            ).scalar_one()

        result = _psql(
            port,
            "GRANT UPDATE(actor_id) ON public.audit_logs TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "audit_logs", "column")
        with app_engine.begin() as conn:
            conn.execute(
                text("UPDATE public.audit_logs SET actor_id=NULL WHERE id=:id"),
                {"id": column_audit_id},
            )
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT actor_id IS NULL FROM audit_logs WHERE id=:id"),
                    {"id": column_audit_id},
                ).scalar_one()
                is True
            )
        assert (
            _psql(
                port,
                "REVOKE UPDATE(actor_id) ON public.audit_logs FROM utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "GRANT SELECT(scope) ON public.security_event_retention_runs TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "security_event_retention_runs", "column")
        with app_engine.begin() as conn:
            conn.execute(
                text("SELECT count(scope) FROM public.security_event_retention_runs")
            ).scalar_one()
        assert (
            _psql(
                port,
                "REVOKE SELECT(scope) ON public.security_event_retention_runs FROM utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        run_columns = (
            "id, run_id, batch_index, scope, cutoff, deleted_count, status, started_at, finished_at"
        )
        result = _psql(
            port,
            f"GRANT INSERT({run_columns}) ON public.security_event_retention_runs TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "security_event_retention_runs", "column")
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO public.security_event_retention_runs "
                    "(id, run_id, batch_index, scope, cutoff, deleted_count, "
                    "status, started_at, finished_at) "
                    "VALUES (999998, "
                    "'11111111-1111-1111-1111-111111111111', 0, "
                    "'success_logout', now() - interval '100 days', 0, "
                    "'success', now(), now())"
                )
            )
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_event_retention_runs WHERE id=999998")
                ).scalar_one()
                == 1
            )
        assert (
            _psql(
                port,
                f"REVOKE INSERT({run_columns}) "
                "ON public.security_event_retention_runs FROM utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "GRANT UPDATE(deleted_count) ON public.security_event_retention_runs TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "security_event_retention_runs", "column")
        with app_engine.begin() as conn:
            conn.execute(text("UPDATE public.security_event_retention_runs SET deleted_count=777"))
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT deleted_count FROM security_event_retention_runs WHERE id=999998")
                ).scalar_one()
                == 777
            )
        assert (
            _psql(
                port,
                "REVOKE UPDATE(deleted_count) "
                "ON public.security_event_retention_runs FROM utop14_app",
            ).returncode
            == 0
        )
        assert (
            _psql(
                port, "DELETE FROM public.security_event_retention_runs WHERE id=999998"
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        with admin.connect() as conn:
            original_head = conn.execute(
                text("SELECT version_num FROM public.alembic_version")
            ).scalar_one()
        result = _psql(
            port,
            "GRANT UPDATE(version_num) ON public.alembic_version TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "alembic_version", "column")
        with app_engine.begin() as conn:
            conn.execute(text("UPDATE public.alembic_version SET version_num='deadbeef'"))
        with admin.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM public.alembic_version")).scalar_one()
                == "deadbeef"
            )
        with admin.begin() as conn:
            conn.execute(
                text("UPDATE public.alembic_version SET version_num=:v"),
                {"v": original_head},
            )
        assert (
            _psql(
                port,
                "REVOKE UPDATE(version_num) ON public.alembic_version FROM utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        # A column grant to an unexpected role is also forbidden.
        for statement in (
            "CREATE ROLE m14314_column_role NOLOGIN",
            "GRANT UPDATE(actor_id) ON public.audit_logs TO m14314_column_role",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14314_column_role", "column")
        for statement in (
            "REVOKE UPDATE(actor_id) ON public.audit_logs FROM m14314_column_role",
            "DROP ROLE m14314_column_role",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # GRANT OPTION is itself an unexpected privilege.
        result = _psql(
            port,
            "GRANT SELECT ON public.audit_logs TO utop14_app WITH GRANT OPTION",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "GRANT OPTION", "audit_logs")
        assert (
            _psql(
                port,
                "REVOKE SELECT ON public.audit_logs FROM utop14_app",
            ).returncode
            == 0
        )
        assert (
            _psql(
                port,
                "GRANT SELECT, INSERT ON public.audit_logs TO utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "GRANT USAGE ON SCHEMA public TO utop14_app WITH GRANT OPTION",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "GRANT OPTION", "schema")
        assert (
            _psql(
                port,
                "REVOKE USAGE ON SCHEMA public FROM utop14_app",
            ).returncode
            == 0
        )
        assert (
            _psql(
                port,
                "GRANT USAGE ON SCHEMA public TO utop14_app",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        with admin.connect() as conn:
            remaining_column_acls = conn.execute(
                text(
                    "SELECT count(*) FROM pg_attribute a "
                    "JOIN pg_class c ON c.oid = a.attrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(a.attacl) x "
                    "WHERE n.nspname='public' "
                    "AND c.relkind IN ('r','p','f') "
                    "AND a.attnum > 0 AND NOT a.attisdropped "
                    "AND a.attacl IS NOT NULL "
                    "AND x.grantee <> c.relowner"
                )
            ).scalar_one()
        assert remaining_column_acls == 0, remaining_column_acls

        # --- M14313-02: database-level CREATE is forbidden -----------------
        for role in ("utop14_retention_owner", "utop14_retention_runner"):
            try:
                with admin.begin() as conn:
                    conn.execute(text(f"SET LOCAL ROLE {role}"))
                    conn.execute(text("CREATE SCHEMA m14314_create_probe"))
                role_created = True
            except SQLAlchemyError:
                role_created = False
            assert role_created is False, role
        try:
            with app_engine.begin() as conn:
                conn.execute(text("CREATE SCHEMA m14314_create_probe"))
            app_created = True
        except SQLAlchemyError:
            app_created = False
        assert app_created is False
        result = _psql(port, "CREATE ROLE m14314_public_probe NOLOGIN")
        assert result.returncode == 0, result.stderr
        try:
            with admin.begin() as conn:
                conn.execute(text("SET LOCAL ROLE m14314_public_probe"))
                conn.execute(text("CREATE SCHEMA m14314_create_probe"))
            public_created = True
        except SQLAlchemyError:
            public_created = False
        assert public_created is False
        assert _psql(port, "DROP ROLE m14314_public_probe").returncode == 0

        result = _psql(port, f"GRANT CREATE ON DATABASE {DB} TO utop14_app")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "database", "CREATE")
        with app_engine.begin() as conn:
            conn.execute(text("CREATE SCHEMA m14314_create_probe"))
        assert _psql(port, "DROP SCHEMA m14314_create_probe CASCADE").returncode == 0
        provisioning_after_db_create = _psql_file(
            port, "scripts/security_event_retention_roles.sql"
        )
        assert provisioning_after_db_create.returncode == 0, (
            provisioning_after_db_create.stdout + provisioning_after_db_create.stderr
        )
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT has_database_privilege('utop14_app', current_database(), 'CREATE')"
                    )
                ).scalar_one()
                is False
            )
        assert _verify(port).returncode == 0

        # PUBLIC CREATE SCHEMA is forbidden and provisioning reconciles it.
        result = _psql(port, f"GRANT CREATE ON DATABASE {DB} TO PUBLIC")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "database", "PUBLIC")
        result = _psql(port, "CREATE ROLE m14314_public_probe NOLOGIN")
        assert result.returncode == 0, result.stderr
        with admin.begin() as conn:
            conn.execute(text("SET LOCAL ROLE m14314_public_probe"))
            conn.execute(text("CREATE SCHEMA m14314_public_create_probe"))
        assert _psql(port, "DROP SCHEMA m14314_public_create_probe CASCADE").returncode == 0
        provisioning_after_public_create = _psql_file(
            port, "scripts/security_event_retention_roles.sql"
        )
        assert provisioning_after_public_create.returncode == 0, (
            provisioning_after_public_create.stdout + provisioning_after_public_create.stderr
        )
        assert _psql(port, "DROP ROLE m14314_public_probe").returncode == 0
        assert _verify(port).returncode == 0

        # --- M14313-03: MAINTAIN is forbidden on PostgreSQL 17+ -----------
        with admin.connect() as conn:
            server_version = conn.execute(
                text("SELECT current_setting('server_version_num')::integer")
            ).scalar_one()
        if server_version >= 170000:
            result = _psql(
                port,
                "GRANT MAINTAIN ON public.audit_logs TO utop14_app",
            )
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "MAINTAIN", "audit_logs")
            provisioning_after_maintain = _psql_file(
                port, "scripts/security_event_retention_roles.sql"
            )
            assert provisioning_after_maintain.returncode == 0, (
                provisioning_after_maintain.stdout + provisioning_after_maintain.stderr
            )
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT has_table_privilege('utop14_app', "
                            "'public.audit_logs', 'MAINTAIN')"
                        )
                    ).scalar_one()
                    is False
                )
            assert _verify(port).returncode == 0

        # --- M14315-01: parameter ACLs and persistent GUCs ----------------
        # Before any grant, the app cannot set a superuser-only GUC.
        try:
            with app_engine.begin() as conn:
                conn.execute(text("SET LOCAL session_preload_libraries = ''"))
            preload_denied = False
        except SQLAlchemyError:
            preload_denied = True
        assert preload_denied is True

        for parameter, runtime_sql in (
            (
                "session_preload_libraries",
                "SET LOCAL session_preload_libraries = ''",
            ),
            ("log_statement", "SET LOCAL log_statement = 'all'"),
        ):
            result = _psql(
                port,
                f"GRANT SET ON PARAMETER {parameter} TO utop14_app",
            )
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "parameter", parameter)
            if parameter == "log_statement":
                shadow = _verify_with_temp_shadow(port)
                shadow_output = shadow.stdout + shadow.stderr
                assert shadow.returncode != 0, shadow_output
                assert "parameter" in shadow_output, shadow_output
            with app_engine.begin() as conn:
                conn.execute(text(runtime_sql))
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text("SELECT has_parameter_privilege('utop14_app', :p, 'SET')"),
                        {"p": parameter},
                    ).scalar_one()
                    is False
                )
            assert _verify(port).returncode == 0

        result = _psql(
            port,
            "GRANT SET ON PARAMETER session_authorization TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "parameter", "session_authorization")
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT has_parameter_privilege("
                        "'utop14_app', 'session_authorization', 'SET')"
                    )
                ).scalar_one()
                is False
            )
        assert _verify(port).returncode == 0

        # PUBLIC parameter grants.
        for parameter, runtime_sql in (
            (
                "session_preload_libraries",
                "SET LOCAL session_preload_libraries = ''",
            ),
            ("log_statement", "SET LOCAL log_statement = 'all'"),
        ):
            result = _psql(
                port,
                f"GRANT SET ON PARAMETER {parameter} TO PUBLIC",
            )
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "parameter", parameter)
            with app_engine.begin() as conn:
                conn.execute(text(runtime_sql))
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT count(*) FROM pg_parameter_acl pa "
                            "CROSS JOIN LATERAL aclexplode(pa.paracl) a "
                            "WHERE pa.parname=:p AND a.grantee=0"
                        ),
                        {"p": parameter},
                    ).scalar_one()
                    == 0
                )
            assert _verify(port).returncode == 0

        # Parameter GRANT OPTION and delegation to PUBLIC.
        result = _psql(
            port,
            "GRANT SET ON PARAMETER log_statement TO utop14_app WITH GRANT OPTION",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "GRANT OPTION", "parameter")
        result = _psql_as(
            port,
            "utop14_app",
            "GRANT SET ON PARAMETER log_statement TO PUBLIC",
        )
        assert result.returncode == 0, result.stderr
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_parameter_acl pa "
                        "CROSS JOIN LATERAL aclexplode(pa.paracl) a "
                        "WHERE pa.parname='log_statement' "
                        "AND (a.grantee=0 OR pg_get_userbyid(a.grantee) IN "
                        "('utop14_app','utop14_retention_owner',"
                        "'utop14_retention_runner'))"
                    )
                ).scalar_one()
                == 0
            )
        assert _verify(port).returncode == 0

        # ALTER SYSTEM parameter privilege.
        result = _psql(
            port,
            "GRANT ALTER SYSTEM ON PARAMETER log_statement TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "ALTER SYSTEM", "parameter")
        altsys = _psql_as(
            port,
            "utop14_app",
            "ALTER SYSTEM SET log_statement = 'all'",
        )
        assert altsys.returncode == 0, altsys.stderr
        assert _psql(port, "ALTER SYSTEM RESET log_statement").returncode == 0
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT has_parameter_privilege("
                        "'utop14_app', 'log_statement', 'ALTER SYSTEM')"
                    )
                ).scalar_one()
                is False
            )
        assert _verify(port).returncode == 0

        # Unrelated custom-role parameter grant passes; an effective membership
        # path fails and is removed by provisioning.
        for statement in (
            "CREATE ROLE m14316_param_role NOLOGIN",
            "GRANT SET ON PARAMETER session_preload_libraries TO m14316_param_role",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0
        result = _psql(
            port,
            "GRANT m14316_param_role TO utop14_app WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "m14316_param_role")
        assert _psql(port, "REVOKE m14316_param_role FROM utop14_app").returncode == 0
        assert _verify(port).returncode == 0
        assert (
            _psql(
                port,
                "REVOKE SET ON PARAMETER session_preload_libraries FROM m14316_param_role",
            ).returncode
            == 0
        )
        assert _psql(port, "DROP ROLE m14316_param_role").returncode == 0
        assert _verify(port).returncode == 0

        # Role-level GUCs: every entry except the approved app search_path fails.
        for statement, needle in (
            (
                "ALTER ROLE utop14_app SET session_preload_libraries = ''",
                "session_preload_libraries",
            ),
            (
                "ALTER ROLE utop14_app SET log_statement = 'all'",
                "log_statement",
            ),
            (
                "ALTER ROLE utop14_app SET work_mem = '64MB'",
                "work_mem",
            ),
            (
                "ALTER ROLE utop14_app SET search_path = pg_catalog, public",
                "search_path",
            ),
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, needle, "utop14_app")
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            with admin.connect() as conn:
                assert conn.execute(
                    text("SELECT rolconfig FROM pg_roles WHERE rolname='utop14_app'")
                ).scalar_one() == ["search_path=public, pg_catalog"]
            assert _verify(port).returncode == 0

        result = _psql(
            port,
            "ALTER ROLE utop14_app SET search_path = public, pg_catalog",
        )
        assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "ALTER ROLE utop14_retention_owner SET work_mem = '64MB'",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "work_mem", "utop14_retention_owner")
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        assert _verify(port).returncode == 0

        # Schema-owner non-search_path settings require DBA reconciliation.
        result = _psql(
            port,
            "ALTER ROLE utop14_schema_owner SET session_preload_libraries = ''",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "session_preload_libraries", "utop14_schema_owner")
        schema_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        schema_failed_output = schema_failed.stdout + schema_failed.stderr
        assert schema_failed.returncode != 0, schema_failed_output
        assert "reconciliation" in schema_failed_output.lower()
        assert (
            _psql(
                port,
                "ALTER ROLE utop14_schema_owner RESET session_preload_libraries",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr

        # Database-specific managed-role GUCs are rejected and reset.
        for statement, role in (
            (
                "ALTER ROLE utop14_app IN DATABASE {db} SET session_preload_libraries = ''",
                "utop14_app",
            ),
            (
                "ALTER ROLE utop14_retention_runner IN DATABASE {db} SET work_mem = '64MB'",
                "utop14_retention_runner",
            ),
            (
                "ALTER ROLE utop14_app IN DATABASE {db} SET search_path = public, pg_catalog",
                "utop14_app",
            ),
        ):
            result = _psql(port, statement.format(db=DB))
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "database-specific", role)
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT count(*) FROM pg_db_role_setting s "
                            "WHERE pg_get_userbyid(s.setrole)=:r "
                            "AND s.setdatabase=("
                            "SELECT oid FROM pg_database "
                            "WHERE datname=current_database()) "
                            "AND s.setconfig IS NOT NULL "
                            "AND array_length(s.setconfig,1) > 0"
                        ),
                        {"r": role},
                    ).scalar_one()
                    == 0
                )
            assert _verify(port).returncode == 0

        # Database-wide settings are DBA-reconciled, never silently changed.
        for setting in (
            "log_statement = 'all'",
            "work_mem = '64MB'",
            "search_path = public, pg_catalog",
        ):
            result = _psql(port, f"ALTER DATABASE {DB} SET {setting}")
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "database-wide")
            failed_provision = _psql_file(port, "scripts/security_event_retention_roles.sql")
            failed_output = failed_provision.stdout + failed_provision.stderr
            assert failed_provision.returncode != 0, failed_output
            assert "database-wide" in failed_output, failed_output
            parameter = setting.split(" = ")[0]
            assert _psql(port, f"ALTER DATABASE {DB} RESET {parameter}").returncode == 0
            assert _verify(port).returncode == 0
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr

        # Ownership template also reconciles parameter grants and GUCs.
        result = _psql(
            port,
            "GRANT SET ON PARAMETER session_preload_libraries TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        result = _psql(
            port,
            "ALTER ROLE utop14_app SET work_mem = '64MB'",
        )
        assert result.returncode == 0, result.stderr
        template_run = _psql_stdin(port, ownership_sql)
        assert template_run.returncode == 0, template_run.stdout + template_run.stderr
        assert _verify(port).returncode == 0

        # The ownership template also fails closed on database-wide and
        # schema-owner GUCs rather than silently changing unrelated settings.
        result = _psql(port, f"ALTER DATABASE {DB} SET work_mem = '64MB'")
        assert result.returncode == 0, result.stderr
        template_db_wide = _psql_stdin(port, ownership_sql)
        template_db_output = template_db_wide.stdout + template_db_wide.stderr
        assert template_db_wide.returncode != 0, template_db_output
        assert "database-wide" in template_db_output, template_db_output
        assert _psql(port, f"ALTER DATABASE {DB} RESET work_mem").returncode == 0
        result = _psql(
            port,
            "ALTER ROLE utop14_schema_owner SET session_preload_libraries = ''",
        )
        assert result.returncode == 0, result.stderr
        template_schema = _psql_stdin(port, ownership_sql)
        template_schema_output = template_schema.stdout + template_schema.stderr
        assert template_schema.returncode != 0, template_schema_output
        assert "reconciliation" in template_schema_output.lower(), template_schema_output
        assert (
            _psql(
                port,
                "ALTER ROLE utop14_schema_owner RESET session_preload_libraries",
            ).returncode
            == 0
        )
        template_recovered = _psql_stdin(port, ownership_sql)
        assert template_recovered.returncode == 0, (
            template_recovered.stdout + template_recovered.stderr
        )
        assert _verify(port).returncode == 0

        with admin.connect() as conn:
            app_config = conn.execute(
                text("SELECT rolconfig FROM pg_roles WHERE rolname='utop14_app'")
            ).scalar_one()
            parameter_grants = conn.execute(
                text(
                    "SELECT count(*) FROM pg_parameter_acl pa "
                    "CROSS JOIN LATERAL aclexplode(pa.paracl) a "
                    "WHERE a.grantee=0 OR pg_get_userbyid(a.grantee) IN "
                    "('utop14_app','utop14_retention_owner',"
                    "'utop14_retention_runner')"
                )
            ).scalar_one()
            db_specific = conn.execute(
                text(
                    "SELECT count(*) FROM pg_db_role_setting s "
                    "WHERE pg_get_userbyid(s.setrole) IN "
                    "('utop14_app','utop14_retention_owner',"
                    "'utop14_retention_runner') "
                    "AND s.setdatabase=("
                    "SELECT oid FROM pg_database "
                    "WHERE datname=current_database()) "
                    "AND s.setconfig IS NOT NULL "
                    "AND array_length(s.setconfig,1) > 0"
                )
            ).scalar_one()
            db_wide = conn.execute(
                text(
                    "SELECT count(*) FROM pg_db_role_setting s "
                    "WHERE s.setrole=0 "
                    "AND s.setdatabase IN (0, ("
                    "SELECT oid FROM pg_database "
                    "WHERE datname=current_database())) "
                    "AND s.setconfig IS NOT NULL "
                    "AND array_length(s.setconfig,1) > 0"
                )
            ).scalar_one()
        assert app_config == ["search_path=public, pg_catalog"], app_config
        assert parameter_grants == 0, parameter_grants
        assert db_specific == 0, db_specific
        assert db_wide == 0, db_wide
        assert _verify(port).returncode == 0
        second_provision = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert second_provision.returncode == 0, second_provision.stdout + second_provision.stderr
        assert _verify(port).returncode == 0
        search_engine = create_engine(_role_dsn(port, "utop14_app"))
        with search_engine.connect() as conn:
            assert conn.execute(text("SHOW search_path")).scalar_one() == "public, pg_catalog"
        search_engine.dispose()

        # --- M14317-01: cross-database managed-role GUCs ------------------
        other_db = "utop14_concurrency_other"
        result = _psql(
            port,
            f"CREATE DATABASE {other_db} OWNER utop14_schema_owner",
        )
        assert result.returncode == 0, result.stderr

        result = _psql(
            port,
            f"ALTER ROLE utop14_app IN DATABASE {other_db} SET work_mem = '64MB'",
        )
        assert result.returncode == 0, result.stderr
        other_engine = create_engine(f"postgresql+psycopg://utop14_app@127.0.0.1:{port}/{other_db}")
        with other_engine.connect() as conn:
            assert conn.execute(text("SHOW work_mem")).scalar_one() == "64MB"
        other_engine.dispose()
        _assert_verify_fails(port, "database-specific", "utop14_app", other_db)
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_db_role_setting s "
                        "WHERE s.setrole='utop14_app'::regrole "
                        "AND s.setdatabase=("
                        "SELECT oid FROM pg_database WHERE datname=:db) "
                        "AND s.setconfig IS NOT NULL "
                        "AND array_length(s.setconfig,1) > 0"
                    ),
                    {"db": other_db},
                ).scalar_one()
                == 0
            )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            f"ALTER ROLE utop14_app IN DATABASE {other_db} SET work_mem = '64MB'",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "database-specific", "utop14_app", other_db)
        template_other = _psql_stdin(port, ownership_sql)
        assert template_other.returncode == 0, template_other.stdout + template_other.stderr
        assert _verify(port).returncode == 0

        for setting in (
            "session_preload_libraries = ''",
            "log_statement = 'all'",
        ):
            result = _psql(
                port,
                f"ALTER ROLE utop14_app IN DATABASE {other_db} SET {setting}",
            )
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "database-specific", "utop14_app", other_db)
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            assert _verify(port).returncode == 0

        for role, setting in (
            ("utop14_retention_runner", "work_mem = '64MB'"),
            ("utop14_retention_owner", "work_mem = '64MB'"),
        ):
            result = _psql(
                port,
                f"ALTER ROLE {role} IN DATABASE {other_db} SET {setting}",
            )
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "database-specific", role, other_db)
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            assert _verify(port).returncode == 0

        result = _psql(
            port,
            "ALTER ROLE utop14_schema_owner "
            f"IN DATABASE {other_db} SET session_preload_libraries = ''",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "database-specific", "utop14_schema_owner", other_db)
        schema_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        schema_output = schema_failed.stdout + schema_failed.stderr
        assert schema_failed.returncode != 0, schema_output
        assert "reconciliation" in schema_output.lower(), schema_output
        assert (
            _psql(
                port,
                "ALTER ROLE utop14_schema_owner "
                f"IN DATABASE {other_db} RESET session_preload_libraries",
            ).returncode
            == 0
        )
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "ALTER ROLE utop14_schema_owner "
            f"IN DATABASE {other_db} SET search_path = public, pg_catalog",
        )
        assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0
        assert (
            _psql(
                port,
                f"ALTER ROLE utop14_schema_owner IN DATABASE {other_db} RESET search_path",
            ).returncode
            == 0
        )

        result = _psql(port, f"ALTER DATABASE {other_db} SET work_mem = '64MB'")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "database-wide", other_db)
        failed_provision = _psql_file(port, "scripts/security_event_retention_roles.sql")
        failed_output = failed_provision.stdout + failed_provision.stderr
        assert failed_provision.returncode != 0, failed_output
        assert "database-wide" in failed_output, failed_output
        assert _psql(port, f"ALTER DATABASE {other_db} RESET work_mem").returncode == 0
        assert _verify(port).returncode == 0

        result = _psql(port, "ALTER ROLE ALL SET work_mem = '64MB'")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "ALL DATABASES")
        failed_global = _psql_file(port, "scripts/security_event_retention_roles.sql")
        global_output = failed_global.stdout + failed_global.stderr
        assert failed_global.returncode != 0, global_output
        assert "database-wide" in global_output, global_output
        assert _psql(port, "ALTER ROLE ALL RESET work_mem").returncode == 0
        assert _verify(port).returncode == 0

        # Unrelated role and unrelated DBA parameter privileges remain.
        for statement in (
            "CREATE ROLE m14318_unrelated LOGIN NOSUPERUSER NOCREATEROLE NOINHERIT",
            "ALTER ROLE m14318_unrelated SET work_mem = '64MB'",
            f"ALTER ROLE m14318_unrelated IN DATABASE {other_db} SET work_mem = '32MB'",
            "CREATE ROLE m14318_param_dba NOLOGIN",
            "GRANT SET ON PARAMETER log_statement TO m14318_param_dba",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0
        provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
        assert _verify(port).returncode == 0
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT has_parameter_privilege('m14318_param_dba','log_statement','SET')")
                ).scalar_one()
                is True
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_db_role_setting s "
                        "WHERE s.setrole='m14318_unrelated'::regrole "
                        "AND s.setdatabase=("
                        "SELECT oid FROM pg_database WHERE datname=:db) "
                        "AND s.setconfig IS NOT NULL "
                        "AND array_length(s.setconfig,1) > 0"
                    ),
                    {"db": other_db},
                ).scalar_one()
                == 1
            )
        for statement in (
            "ALTER ROLE m14318_unrelated RESET ALL",
            f"ALTER ROLE m14318_unrelated IN DATABASE {other_db} RESET ALL",
            "REVOKE SET ON PARAMETER log_statement FROM m14318_param_dba",
            "DROP ROLE m14318_param_dba",
            "DROP ROLE m14318_unrelated",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr

        # Schema-owner parameter ACLs: direct, ALTER SYSTEM, GRANT OPTION.
        for statement in (
            "GRANT SET ON PARAMETER log_statement TO utop14_schema_owner",
            "GRANT ALTER SYSTEM ON PARAMETER log_statement "
            "TO utop14_schema_owner WITH GRANT OPTION",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
            _assert_verify_fails(port, "parameter", "utop14_schema_owner")
            provisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
            assert provisioned.returncode == 0, provisioned.stdout + provisioned.stderr
            assert _verify(port).returncode == 0

        # Cluster-level postgresql.auto.conf settings are detected and block
        # provisioning until the DBA reconciles them.
        result = _psql(port, "ALTER SYSTEM SET log_statement = 'all'")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "postgresql.auto.conf", "log_statement")
        altsys_provision = _psql_file(port, "scripts/security_event_retention_roles.sql")
        altsys_output = altsys_provision.stdout + altsys_provision.stderr
        assert altsys_provision.returncode != 0, altsys_output
        assert "postgresql.auto.conf" in altsys_output, altsys_output
        assert _psql(port, "ALTER SYSTEM RESET log_statement").returncode == 0
        assert _verify(port).returncode == 0

        result = _psql(port, "ALTER SYSTEM SET search_path = public, pg_catalog")
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "postgresql.auto.conf", "search_path")
        assert _psql(port, "ALTER SYSTEM RESET search_path").returncode == 0
        assert _verify(port).returncode == 0

        # Reliable failure after cross-database resets: the GRANT event
        # trigger aborts after the reset loop; the transaction must roll back
        # the cross-database setting, and a rerun must reconcile it.
        result = _psql(
            port,
            f"ALTER ROLE utop14_app IN DATABASE {other_db} SET work_mem = '64MB'",
        )
        assert result.returncode == 0, result.stderr
        for statement in (
            "CREATE FUNCTION pg_catalog.m14318_fail_on_grant() "
            "RETURNS event_trigger LANGUAGE plpgsql AS $$ "
            "BEGIN "
            "IF EXISTS (SELECT 1 FROM pg_event_trigger_ddl_commands() "
            "WHERE command_tag = 'GRANT') THEN "
            "RAISE EXCEPTION 'injected cross-database failure'; "
            "END IF; END $$",
            "CREATE EVENT TRIGGER m14318_fail_on_grant ON ddl_command_end "
            "EXECUTE FUNCTION pg_catalog.m14318_fail_on_grant()",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        cross_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        cross_failed_output = cross_failed.stdout + cross_failed.stderr
        assert cross_failed.returncode != 0, cross_failed_output
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_db_role_setting s "
                        "WHERE s.setrole='utop14_app'::regrole "
                        "AND s.setdatabase=("
                        "SELECT oid FROM pg_database WHERE datname=:db) "
                        "AND s.setconfig IS NOT NULL "
                        "AND array_length(s.setconfig,1) > 0"
                    ),
                    {"db": other_db},
                ).scalar_one()
                == 1
            )
        _assert_verify_fails(port, "database-specific", "utop14_app", other_db)
        assert _psql(port, "DROP EVENT TRIGGER m14318_fail_on_grant").returncode == 0
        assert (
            _psql(
                port,
                "DROP FUNCTION pg_catalog.m14318_fail_on_grant()",
            ).returncode
            == 0
        )
        cross_recovered = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert cross_recovered.returncode == 0, cross_recovered.stdout + cross_recovered.stderr
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM pg_db_role_setting s "
                        "WHERE s.setrole='utop14_app'::regrole "
                        "AND s.setdatabase=("
                        "SELECT oid FROM pg_database WHERE datname=:db) "
                        "AND s.setconfig IS NOT NULL "
                        "AND array_length(s.setconfig,1) > 0"
                    ),
                    {"db": other_db},
                ).scalar_one()
                == 0
            )
        assert _verify(port).returncode == 0

        assert _psql(port, f"DROP DATABASE {other_db}").returncode == 0
        assert _verify(port).returncode == 0

        # --- M14319-01 / M14.3.20: complete-verifier catalog shadowing ------
        #
        # A temporary relation shadows the same-named catalog for every
        # unqualified reference (pg_temp is searched before pg_catalog for
        # relation names), so a verifier that resolves pg_class, pg_attribute,
        # pg_proc, ... through the search path can be made to return a false
        # PASS.  Each case below must still fail closed.
        ok_marker = "ALL REQUIRED APPLICATION AND RETENTION PRIVILEGE CHECKS PASSED"
        result = _psql(
            port,
            "GRANT SELECT ON public.audit_logs TO utop14_app WITH GRANT OPTION",
        )
        assert result.returncode == 0, result.stderr
        _assert_verify_fails(port, "GRANT OPTION")

        # The prohibited capability is real: with GRANT OPTION the app can
        # widen audit-log visibility, which is exactly what the verifier must
        # never bless.
        with app_engine.begin() as conn:
            conn.execute(text("GRANT SELECT ON public.audit_logs TO PUBLIC"))
        # The grant was made by utop14_app as grantor; a superuser REVOKE acts
        # as the object owner and would not remove it, so revoke as the grantor.
        with app_engine.begin() as conn:
            conn.execute(text("REVOKE SELECT ON public.audit_logs FROM PUBLIC"))

        catalog_shadows = {
            "pg_class": (
                "CREATE TEMP TABLE pg_class "
                "AS SELECT * FROM pg_catalog.pg_class; "
                "UPDATE pg_class SET relacl = NULL "
                "WHERE relname = 'audit_logs';"
            ),
            "pg_attribute": (
                "CREATE TEMP TABLE pg_attribute "
                "(attrelid, attname, atttypid, attacl, attnum, attisdropped) "
                "AS SELECT attrelid, attname, atttypid, attacl, attnum, "
                "attisdropped FROM pg_catalog.pg_attribute; "
                "DELETE FROM pg_attribute "
                "WHERE attrelid = 'public.audit_logs'::regclass;"
            ),
            "pg_proc": (
                "CREATE TEMP TABLE pg_proc "
                "AS SELECT * FROM pg_catalog.pg_proc; "
                "DELETE FROM pg_proc;"
            ),
            "pg_namespace": (
                "CREATE TEMP TABLE pg_namespace "
                "AS SELECT * FROM pg_catalog.pg_namespace; "
                "DELETE FROM pg_namespace WHERE nspname = 'public';"
            ),
            "pg_depend": (
                "CREATE TEMP TABLE pg_depend "
                "AS SELECT * FROM pg_catalog.pg_depend; "
                "DELETE FROM pg_depend;"
            ),
            "pg_type": (
                "CREATE TEMP TABLE pg_type "
                "AS SELECT * FROM pg_catalog.pg_type; "
                "DELETE FROM pg_type;"
            ),
            "pg_trigger": (
                "CREATE TEMP TABLE pg_trigger "
                "AS SELECT * FROM pg_catalog.pg_trigger; "
                "DELETE FROM pg_trigger;"
            ),
            "pg_extension": (
                "CREATE TEMP TABLE pg_extension "
                "AS SELECT * FROM pg_catalog.pg_extension; "
                "DELETE FROM pg_extension;"
            ),
        }
        for catalog, shadow_sql in catalog_shadows.items():
            shadowed = _verify_with_catalog_shadow(port, shadow_sql)
            shadowed_output = shadowed.stdout + shadowed.stderr
            assert shadowed.returncode != 0, (
                f"{catalog} shadow produced a false PASS:\n{shadowed_output}"
            )
            assert ok_marker not in shadowed_output, (
                f"{catalog} shadow produced a false PASS:\n{shadowed_output}"
            )
            if catalog in ("pg_class", "pg_attribute"):
                assert "GRANT OPTION" in shadowed_output, (
                    f"{catalog} shadow hid the table ACL finding:\n{shadowed_output}"
                )

        # Temporary functions named like catalog helpers are not implicitly
        # searched (pg_temp is never searched for function names), but a
        # falsely-resolving helper must not be able to suppress the finding.
        temp_function_shadow = (
            "CREATE FUNCTION pg_temp.has_table_privilege("
            "name, text, text) RETURNS boolean LANGUAGE sql "
            "AS 'SELECT false'; "
            "CREATE FUNCTION pg_temp.has_column_privilege("
            "name, text, text, text) RETURNS boolean LANGUAGE sql "
            "AS 'SELECT false'; "
            "CREATE FUNCTION pg_temp.has_schema_privilege("
            "name, text, text) RETURNS boolean LANGUAGE sql "
            "AS 'SELECT false';"
        )
        temp_functions = _verify_with_catalog_shadow(port, temp_function_shadow)
        temp_function_output = temp_functions.stdout + temp_functions.stderr
        assert temp_functions.returncode != 0, temp_function_output
        assert ok_marker not in temp_function_output, temp_function_output
        assert "GRANT OPTION" in temp_function_output, temp_function_output

        # Hostile ordinary schema: the verifier sets its own search_path, so
        # shadow objects in a caller-controlled schema cannot be reached.
        hostile_setup = (
            "CREATE SCHEMA m14320_hostile; "
            "CREATE TABLE m14320_hostile.pg_class "
            "(oid oid, relname text, relacl aclitem[]); "
            "CREATE TABLE m14320_hostile.pg_attribute "
            "(attrelid oid, attname text, attacl aclitem[]); "
            "CREATE TABLE m14320_hostile.pg_namespace "
            "(oid oid, nspname text); "
            "CREATE FUNCTION m14320_hostile.has_table_privilege("
            "name, text, text) RETURNS boolean LANGUAGE sql "
            "AS 'SELECT false';"
        )
        assert _psql(port, hostile_setup).returncode == 0
        hostile = _verify_with_search_path(port, "m14320_hostile,public")
        hostile_output = hostile.stdout + hostile.stderr
        assert hostile.returncode != 0, hostile_output
        assert ok_marker not in hostile_output, hostile_output
        assert _psql(port, "DROP SCHEMA m14320_hostile CASCADE").returncode == 0
        _assert_verify_fails(port, "GRANT OPTION")

        def grant_option_count() -> int:
            with admin.connect() as conn:
                return conn.execute(
                    text(
                        "SELECT count(*) FROM pg_catalog.pg_class c "
                        "CROSS JOIN LATERAL pg_catalog.aclexplode("
                        "COALESCE(c.relacl, "
                        "pg_catalog.acldefault('r', c.relowner))) a "
                        "WHERE c.oid = 'public.audit_logs'::regclass "
                        "AND a.grantee = 'utop14_app'::regrole "
                        "AND a.is_grantable"
                    )
                ).scalar_one()

        # Provisioning under a shadowed catalog must resolve the real catalog
        # and remove the GRANT OPTION, not skip the table and report success.
        for catalog in ("pg_class", "pg_depend", "pg_proc"):
            result = _psql(
                port,
                "GRANT SELECT ON public.audit_logs TO utop14_app WITH GRANT OPTION",
            )
            assert result.returncode == 0, result.stderr
            provisioned_shadow = _psql_file_with_shadow(
                port,
                catalog_shadows[catalog],
                "scripts/security_event_retention_roles.sql",
            )
            provisioned_output = provisioned_shadow.stdout + provisioned_shadow.stderr
            assert provisioned_shadow.returncode == 0, (
                f"{catalog} shadow broke provisioning:\n{provisioned_output}"
            )
            assert grant_option_count() == 0, catalog
            assert _verify(port).returncode == 0, catalog

        # Ownership template under a shadowed pg_class must still see the real
        # object inventory.  The template deliberately fails closed when the
        # app already owns an object, so the shadow must not turn that into a
        # silent success that skips the transfer.
        assert _psql(port, "GRANT CREATE ON SCHEMA public TO utop14_app").returncode == 0
        assert (
            _psql(
                port,
                "ALTER TABLE public.audit_logs OWNER TO utop14_app",
            ).returncode
            == 0
        )
        assert _psql(port, "REVOKE CREATE ON SCHEMA public FROM utop14_app").returncode == 0
        assert _verify(port).returncode != 0
        for catalog in ("pg_class", "pg_proc", "pg_depend", "pg_namespace"):
            template_shadow = _psql_stdin_with_shadow(port, catalog_shadows[catalog], ownership_sql)
            template_output = template_shadow.stdout + template_shadow.stderr
            assert template_shadow.returncode != 0, (
                f"{catalog} shadow made the template silently succeed:\n{template_output}"
            )
            if catalog == "pg_class":
                # The shadow must not hide the stray app-owned table.
                assert "already owns" in template_output, template_output
            with admin.connect() as conn:
                shadowed_owner = conn.execute(
                    text(
                        "SELECT pg_catalog.pg_get_userbyid(relowner) "
                        "FROM pg_catalog.pg_class "
                        "WHERE oid = 'public.audit_logs'::regclass"
                    )
                ).scalar_one()
            assert shadowed_owner == "utop14_app", (catalog, shadowed_owner)
        unshadowed_template = _psql_stdin(port, ownership_sql)
        unshadowed_output = unshadowed_template.stdout + unshadowed_template.stderr
        assert unshadowed_template.returncode != 0, unshadowed_output
        assert "already owns" in unshadowed_output, unshadowed_output
        with admin.connect() as conn:
            audit_owner = conn.execute(
                text(
                    "SELECT pg_catalog.pg_get_userbyid(relowner) "
                    "FROM pg_catalog.pg_class "
                    "WHERE oid = 'public.audit_logs'::regclass"
                )
            ).scalar_one()
        assert audit_owner == "utop14_app", audit_owner
        assert (
            _psql(
                port,
                "ALTER TABLE public.audit_logs OWNER TO utop14_schema_owner",
            ).returncode
            == 0
        )
        # Changing ownership drops the new owner's explicit ACL entries, so
        # re-apply the canonical privilege matrix through provisioning.
        reprovisioned = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert reprovisioned.returncode == 0, reprovisioned.stdout + reprovisioned.stderr
        assert _verify(port).returncode == 0

        # --- M14313-05: hostile schema / caller search_path ----------------
        for statement in (
            "CREATE SCHEMA m14314_hostile",
            "CREATE TABLE m14314_hostile.audit_logs (id integer, actor_email text)",
            "GRANT SELECT ON m14314_hostile.audit_logs TO utop14_app",
            "CREATE FUNCTION m14314_hostile.has_table_privilege("
            "text, text, text) RETURNS boolean LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'shadow function called'; END $$",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        hostile = _verify_with_search_path(port, "m14314_hostile,public")
        hostile_output = hostile.stdout + hostile.stderr
        assert hostile.returncode != 0, hostile_output
        assert "m14314_hostile" in hostile_output, hostile_output
        assert _psql(port, "DROP SCHEMA m14314_hostile CASCADE").returncode == 0
        assert _verify(port).returncode == 0

        # deny row mutation even when table privileges are present.
        for statement in (
            "CREATE ROLE utop14_trigger_tester LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
            "GRANT USAGE ON SCHEMA public TO utop14_trigger_tester",
            "GRANT SELECT, UPDATE, DELETE ON public.audit_logs, "
            "public.security_events TO utop14_trigger_tester",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr

        trigger_engine = create_engine(_role_dsn(port, "utop14_trigger_tester"))
        for statement, params in (
            (
                "UPDATE public.audit_logs SET actor_email='changed@example.com' WHERE id=:id",
                {"id": audit_id},
            ),
            ("DELETE FROM public.audit_logs WHERE id=:id", {"id": audit_id}),
            (
                "UPDATE public.security_events SET user_agent='changed' WHERE id=:id",
                {"id": throttle_event_id},
            ),
            (
                "DELETE FROM public.security_events WHERE id=:id",
                {"id": throttle_event_id},
            ),
        ):
            try:
                with trigger_engine.begin() as conn:
                    conn.execute(text(statement), params)
                raise AssertionError(f"trigger tester unexpectedly executed: {statement}")
            except SQLAlchemyError as exc:
                assert "append-only" in str(exc), str(exc)
        for table in ("audit_logs", "security_events"):
            try:
                with trigger_engine.begin() as conn:
                    conn.execute(text(f"TRUNCATE {table}"))
                raise AssertionError(f"trigger tester unexpectedly truncated {table}")
            except SQLAlchemyError as exc:
                assert "permission denied" in str(exc).lower(), str(exc)
        try:
            with trigger_engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE public.audit_logs DISABLE TRIGGER audit_logs_append_only")
                )
            raise AssertionError("trigger tester disabled audit_logs trigger")
        except SQLAlchemyError as exc:
            assert "must be owner" in str(exc).lower(), str(exc)

        # The trigger tester is a temporary probe role.  Remove its grants so
        # the complete table ACL matrix stays clean for later verification.
        trigger_engine.dispose()
        result = _psql(port, "DROP OWNED BY utop14_trigger_tester")
        assert result.returncode == 0, result.stderr
        result = _psql(port, "DROP ROLE utop14_trigger_tester")
        assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # --- Function validation ------------------------------------------
        for statement, needle in (
            (
                "SELECT public.prune_security_events(NULL, "
                "now() - interval '200 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, 0)",
                "invalid retention scope",
            ),
            (
                "SELECT public.prune_security_events('success_logout', "
                "now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, 100)",
                "invalid retention batch index",
            ),
            (
                "SELECT public.prune_security_events('success_logout', "
                "now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, -1)",
                "invalid retention batch index",
            ),
            (
                "SELECT public.prune_security_events('success_logout', "
                "now() - interval '100 days', 10, "
                "'00000000-0000-0000-0000-000000000000'::uuid, NULL)",
                "invalid retention batch index",
            ),
        ):
            try:
                with runner.begin() as conn:
                    conn.execute(text(statement))
                raise AssertionError(f"function accepted invalid parameters: {statement}")
            except SQLAlchemyError as exc:
                assert needle in str(exc), (needle, str(exc))

        with runner.begin() as conn:
            assert (
                conn.execute(
                    text(
                        "SELECT public.prune_security_events('success_logout', "
                        "now() - interval '100 days', 10, "
                        "'00000000-0000-0000-0000-000000000000'::uuid, 0)"
                    )
                ).scalar_one()
                == 0
            )
            assert (
                conn.execute(
                    text(
                        "SELECT public.prune_security_events('success_logout', "
                        "now() - interval '100 days', 10, "
                        "'00000000-0000-0000-0000-000000000000'::uuid, 99)"
                    )
                ).scalar_one()
                == 0
            )

        # --- Active and expired holds -------------------------------------
        active = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with app_engine.begin() as conn:
            conn.execute(text("SELECT pg_advisory_xact_lock(7381, :id)"), {"id": active})
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'active', 'operator', now() + interval '1 day')"
                ),
                {"id": active},
            )
        assert _prune(runner, scope="success_logout", cutoff=now - timedelta(days=90)) == 0
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": active}
                ).scalar_one()
                == 1
            )

        expired = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with admin.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, created_at, expires_at) "
                    "VALUES (:id, 'expired', 'operator', "
                    "now() - interval '2 hours', now() - interval '1 hour')"
                ),
                {"id": expired},
            )
        _prune(runner, scope="success_logout", cutoff=now - timedelta(days=90))
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": expired}
                ).scalar_one()
                == 0
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM security_event_retention_holds h "
                        "LEFT JOIN security_events e ON e.id=h.security_event_id "
                        "WHERE e.id IS NULL"
                    )
                ).scalar_one()
                == 0
            )

        # --- Duplicate hold ------------------------------------------------
        duplicate = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'first', 'op', now() + interval '1 day')"
                ),
                {"id": duplicate},
            )
        try:
            with app_engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO security_event_retention_holds "
                        "(security_event_id, reason, created_by, expires_at) "
                        "VALUES (:id, 'second', 'op', now() + interval '2 days')"
                    ),
                    {"id": duplicate},
                )
            raise AssertionError("duplicate hold was accepted")
        except SQLAlchemyError:
            pass

        # --- Direct INSERT race (M14331-02) --------------------------------
        direct = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        direct_ready = threading.Event()
        direct_deleted: dict[str, int] = {}

        def direct_insert() -> None:
            with app_engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO security_event_retention_holds "
                        "(security_event_id, reason, created_by, expires_at) "
                        "VALUES (:id, 'direct', 'op', now() + interval '1 day')"
                    ),
                    {"id": direct},
                )
                direct_ready.set()
                time.sleep(0.4)

        def direct_cleanup() -> None:
            direct_ready.wait(timeout=5)
            direct_deleted["n"] = _prune(
                runner, scope="success_logout", cutoff=now - timedelta(days=90)
            )

        t1 = threading.Thread(target=direct_insert)
        t2 = threading.Thread(target=direct_cleanup)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)
        with admin.connect() as conn:
            event_count = conn.execute(
                text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": direct}
            ).scalar_one()
            hold_count = conn.execute(
                text(
                    "SELECT count(*) FROM security_event_retention_holds "
                    "WHERE security_event_id=:id"
                ),
                {"id": direct},
            ).scalar_one()
        assert direct_deleted.get("n") == 0, direct_deleted
        assert event_count == 1 and hold_count == 1, (event_count, hold_count)

        # --- Direct UPDATE expiry rejection --------------------------------
        protected = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'protected', 'op', now() + interval '1 day')"
                ),
                {"id": protected},
            )
        try:
            with app_engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE security_event_retention_holds "
                        "SET created_at=now() - interval '2 hours', "
                        "expires_at=now() - interval '1 hour' "
                        "WHERE security_event_id=:id"
                    ),
                    {"id": protected},
                )
            raise AssertionError("active hold was expired by direct UPDATE")
        except SQLAlchemyError as exc:
            assert "active investigative holds cannot be expired or shortened" in str(exc)
        assert _prune(runner, scope="success_logout", cutoff=now - timedelta(days=90)) == 0
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": protected}
                ).scalar_one()
                == 1
            )

        # --- Move a hold to another event ---------------------------------
        first = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        second = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with app_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'moving', 'op', now() + interval '1 day')"
                ),
                {"id": first},
            )
            conn.execute(
                text(
                    "UPDATE security_event_retention_holds "
                    "SET security_event_id=:second WHERE security_event_id=:first"
                ),
                {"first": first, "second": second},
            )
        _prune(runner, scope="success_logout", cutoff=now - timedelta(days=90))
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": first}
                ).scalar_one()
                == 0
            )
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": second}
                ).scalar_one()
                == 1
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM security_event_retention_holds "
                        "WHERE security_event_id=:id"
                    ),
                    {"id": second},
                ).scalar_one()
                == 1
            )

        # --- RR-07: concurrent hold moves A->B and B->A -------------------
        move_a = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        move_b = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        with app_engine.begin() as conn:
            move_hold_id = conn.execute(
                text(
                    "INSERT INTO security_event_retention_holds "
                    "(security_event_id, reason, created_by, expires_at) "
                    "VALUES (:id, 'concurrent-move', 'op', now() + interval '1 day') "
                    "RETURNING id"
                ),
                {"id": move_a},
            ).scalar_one()

        move_barrier = threading.Barrier(2)
        move_errors: dict[int, str] = {}

        def move_hold(target: int) -> None:
            move_barrier.wait(timeout=5)
            try:
                with app_engine.begin() as conn:
                    conn.execute(text("SET LOCAL lock_timeout = '5s'"))
                    conn.execute(
                        text(
                            "UPDATE security_event_retention_holds "
                            "SET security_event_id=:target WHERE id=:hold_id"
                        ),
                        {"target": target, "hold_id": move_hold_id},
                    )
                    time.sleep(0.2)
            except SQLAlchemyError as exc:
                move_errors[target] = str(exc)

        t_move_a = threading.Thread(target=move_hold, args=(move_b,))
        t_move_b = threading.Thread(target=move_hold, args=(move_a,))
        t_move_a.start()
        t_move_b.start()
        t_move_a.join(timeout=10)
        t_move_b.join(timeout=10)
        assert not t_move_a.is_alive() and not t_move_b.is_alive(), "hold move hung"
        assert not move_errors, move_errors

        with admin.connect() as conn:
            final_holder = conn.execute(
                text("SELECT security_event_id FROM security_event_retention_holds WHERE id=:id"),
                {"id": move_hold_id},
            ).scalar_one()
            both_exist = conn.execute(
                text("SELECT count(*) FROM security_events WHERE id IN (:a,:b)"),
                {"a": move_a, "b": move_b},
            ).scalar_one()
        assert final_holder in (move_a, move_b), final_holder
        assert both_exist == 2, both_exist

        _prune(runner, scope="success_logout", cutoff=now - timedelta(days=90))
        with admin.connect() as conn:
            held_event = conn.execute(
                text("SELECT security_event_id FROM security_event_retention_holds WHERE id=:id"),
                {"id": move_hold_id},
            ).scalar_one()
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"),
                    {"id": held_event},
                ).scalar_one()
                == 1
            )
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id IN (:a,:b)"),
                    {"a": move_a, "b": move_b},
                ).scalar_one()
                == 1
            )
            orphan = conn.execute(
                text(
                    "SELECT count(*) FROM security_event_retention_holds h "
                    "LEFT JOIN security_events e ON e.id = h.security_event_id "
                    "WHERE e.id IS NULL"
                )
            ).scalar_one()
            assert orphan == 0

        # --- Hold-first and cleanup-first races ---------------------------
        hold_first = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        hold_ready = threading.Event()
        hold_first_deleted: dict[str, int] = {}

        def hold_first_hold() -> None:
            with app_engine.begin() as conn:
                conn.execute(text("SELECT pg_advisory_xact_lock(7381, :id)"), {"id": hold_first})
                hold_ready.set()
                time.sleep(0.3)
                conn.execute(
                    text(
                        "INSERT INTO security_event_retention_holds "
                        "(security_event_id, reason, created_by, expires_at) "
                        "VALUES (:id, 'hold-first', 'op', now() + interval '1 day')"
                    ),
                    {"id": hold_first},
                )

        def hold_first_cleanup() -> None:
            hold_ready.wait(timeout=5)
            hold_first_deleted["n"] = _prune(
                runner, scope="success_logout", cutoff=now - timedelta(days=90)
            )

        t3 = threading.Thread(target=hold_first_hold)
        t4 = threading.Thread(target=hold_first_cleanup)
        t3.start()
        t4.start()
        t3.join(timeout=10)
        t4.join(timeout=10)
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"), {"id": hold_first}
                ).scalar_one()
                == 1
            )
        assert hold_first_deleted.get("n") == 0, hold_first_deleted

        cleanup_first = _insert_event(
            schema_owner,
            event_type="auth.logout",
            outcome="success",
            reason="user_requested",
            created_at=now - timedelta(days=120),
        )
        cleanup_locked = threading.Event()
        cleanup_first_hold_ok: dict[str, bool] = {}

        def cleanup_first_cleanup() -> None:
            with runner.begin() as conn:
                conn.execute(text("SELECT pg_advisory_xact_lock(7381, :id)"), {"id": cleanup_first})
                cleanup_locked.set()
                time.sleep(0.3)
                conn.execute(
                    text(
                        "SELECT public.prune_security_events("
                        "'success_logout', :cutoff, 100, CAST(:run_id AS uuid), 0)"
                    ),
                    {
                        "cutoff": now - timedelta(days=90),
                        "run_id": str(uuid.uuid4()),
                    },
                )

        def cleanup_first_hold() -> None:
            cleanup_locked.wait(timeout=5)
            try:
                with app_engine.begin() as conn:
                    conn.execute(
                        text("SELECT pg_advisory_xact_lock(7381, :id)"),
                        {"id": cleanup_first},
                    )
                    conn.execute(
                        text(
                            "INSERT INTO security_event_retention_holds "
                            "(security_event_id, reason, created_by, expires_at) "
                            "VALUES (:id, 'late', 'op', now() + interval '1 day')"
                        ),
                        {"id": cleanup_first},
                    )
                cleanup_first_hold_ok["ok"] = True
            except SQLAlchemyError:
                cleanup_first_hold_ok["ok"] = False

        t5 = threading.Thread(target=cleanup_first_cleanup)
        t6 = threading.Thread(target=cleanup_first_hold)
        t5.start()
        t6.start()
        t5.join(timeout=10)
        t6.join(timeout=10)
        with admin.connect() as conn:
            assert (
                conn.execute(
                    text("SELECT count(*) FROM security_events WHERE id=:id"),
                    {"id": cleanup_first},
                ).scalar_one()
                == 0
            )
            assert (
                conn.execute(
                    text(
                        "SELECT count(*) FROM security_event_retention_holds "
                        "WHERE security_event_id=:id"
                    ),
                    {"id": cleanup_first},
                ).scalar_one()
                == 0
            )
        assert cleanup_first_hold_ok.get("ok") is False

        # --- M14311-03: provisioning reconciles a forbidden membership ------
        result = _psql(
            port,
            "GRANT pg_write_all_data TO utop14_app WITH SET TRUE, INHERIT FALSE",
        )
        assert result.returncode == 0, result.stderr
        healed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        healed_output = healed.stdout + healed.stderr
        assert healed.returncode == 0, healed_output
        assert "REVOKED forbidden membership" in healed_output
        with admin.connect() as conn:
            remaining_memberships = conn.execute(
                text(
                    "SELECT count(*) FROM pg_auth_members m "
                    "JOIN pg_roles u ON u.oid = m.member "
                    "WHERE u.rolname IN ('utop14_app', "
                    "'utop14_retention_owner', 'utop14_retention_runner')"
                )
            ).scalar_one()
        assert remaining_memberships == 0, remaining_memberships
        assert _verify(port).returncode == 0

        # --- M14311-03: failure injection and recoverable rerun -------------
        acl_before_failure = _acl_snapshot(admin)
        owners_before_failure = _owner_snapshot(admin)
        result = _psql(port, "ALTER ROLE utop14_retention_owner SUPERUSER")
        assert result.returncode == 0, result.stderr
        failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        failed_output = failed.stdout + failed.stderr
        assert failed.returncode != 0, failed_output
        assert "incompatible privileged attributes" in failed_output, failed_output
        # Preflight failure must leave no partial grants/ownership changes.
        assert _acl_snapshot(admin) == acl_before_failure
        assert _owner_snapshot(admin) == owners_before_failure
        assert _psql(port, "ALTER ROLE utop14_retention_owner NOSUPERUSER").returncode == 0
        recovered = _psql_file(port, "scripts/security_event_retention_roles.sql")
        assert recovered.returncode == 0, recovered.stdout + recovered.stderr
        assert _verify(port).returncode == 0

        # A reverse membership fails provisioning preflight without changes.
        for statement in (
            "CREATE ROLE m14312_reverse_provision NOLOGIN",
            "GRANT utop14_app TO m14312_reverse_provision",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        reverse_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        reverse_output = reverse_failed.stdout + reverse_failed.stderr
        assert reverse_failed.returncode != 0, reverse_output
        assert "reverse membership" in reverse_output, reverse_output
        assert _acl_snapshot(admin) == acl_before_failure
        assert _owner_snapshot(admin) == owners_before_failure
        for statement in (
            "REVOKE utop14_app FROM m14312_reverse_provision",
            "DROP ROLE m14312_reverse_provision",
        ):
            result = _psql(port, statement)
            assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0

        # Unexpected schema and dangerous default ACL fail provisioning
        # preflight before any change; cleanup restores a passing state.
        result = _psql(port, "CREATE SCHEMA m14312_provision_schema")
        assert result.returncode == 0, result.stderr
        schema_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        schema_output = schema_failed.stdout + schema_failed.stderr
        assert schema_failed.returncode != 0, schema_output
        assert "uninventoried non-system schemas" in schema_output, schema_output
        assert _psql(port, "DROP SCHEMA m14312_provision_schema").returncode == 0
        assert _verify(port).returncode == 0

        result = _psql(
            port,
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO utop14_app",
        )
        assert result.returncode == 0, result.stderr
        acl_failed = _psql_file(port, "scripts/security_event_retention_roles.sql")
        acl_output = acl_failed.stdout + acl_failed.stderr
        assert acl_failed.returncode != 0, acl_output
        assert "dangerous custom default privilege" in acl_output, acl_output
        result = _psql(
            port,
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM utop14_app",
        )
        assert result.returncode == 0, result.stderr
        assert _verify(port).returncode == 0
    finally:
        try:
            if (data_dir / "postmaster.pid").exists():
                _run(str(pg_bin / "pg_ctl"), "-D", str(data_dir), "stop", "-m", "fast")
        finally:
            shutil.rmtree(data_dir, ignore_errors=True)
