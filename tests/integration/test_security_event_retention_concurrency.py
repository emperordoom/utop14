"""Disposable PostgreSQL ownership and hold-concurrency regression tests.

These tests are intentionally gated: set ``UTOP14_DISPOSABLE_PG=1`` to run
them.  They create a throwaway PostgreSQL cluster, run all migrations as a
dedicated schema owner, provision the retention roles as a superuser, and then
verify OPS-01 ownership separation plus the M14331-02 hold races.

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
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app import create_app

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
        assert "ALL REQUIRED RETENTION PRIVILEGE CHECKS PASSED" in combined_verification

        admin = create_engine(f"postgresql+psycopg://postgres@127.0.0.1:{port}/{DB}")
        schema_owner = create_engine(schema_owner_dsn)
        app_engine = create_engine(_role_dsn(port, "utop14_app"))
        runner = create_engine(_role_dsn(port, "utop14_retention_runner"))
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
    finally:
        try:
            if (data_dir / "postmaster.pid").exists():
                _run(str(pg_bin / "pg_ctl"), "-D", str(data_dir), "stop", "-m", "fast")
        finally:
            shutil.rmtree(data_dir, ignore_errors=True)
