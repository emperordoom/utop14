"""Harden the security-event retention run log and preserve DB-time integrity.

Revision ID: f5d2b8c3e1a6
Revises: c4a9e2f7b1d8
Create Date: 2026-11-06 12:00:00.000000

M14.5.1.1 remediation for B-03 (time-source consistency) and B-05 (run-log
integrity).

* Adds the ``started`` run status used by the two-phase protocol.
* Adds ``executed_by`` (NOT NULL, historical rows backfilled to ``legacy``).
* Adds UNIQUE ``(run_id, batch_index)``.  The migration fails closed with an
  explicit reconciliation message when duplicate historical rows exist; it
  never deletes or merges run-log history.
* Replaces ``prune_security_events`` so it can only record a success for a
  previously started row owned by the calling ``session_user``.
* Adds ``begin_retention_run`` and ``abandon_retention_run``.

The migration is forward-only for production.  Downgrade is allowed only when
the run-log table is empty; it refuses to drop the new column or functions while
any historical run row exists.  Production rollback is restore-from-backup, not
a destructive downgrade.

Ownership note: ``CREATE OR REPLACE FUNCTION`` preserves the existing owner.  A
migration run after provisioning must be executed by the DBA/superuser (or after
temporarily transferring ownership), because the schema/DDL role cannot replace
a function owned by ``utop14_retention_owner``.  Role-dependent ownership and
EXECUTE grants are applied conditionally when the roles already exist and are
re-applied authoritatively by ``scripts/security_event_retention_roles.sql``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f5d2b8c3e1a6"
down_revision = "c4a9e2f7b1d8"
branch_labels = None
depends_on = None


_BEGIN_FUNCTION = """
CREATE OR REPLACE FUNCTION public.begin_retention_run(
    p_scope text,
    p_cutoff timestamp with time zone,
    p_run_id uuid,
    p_batch_index integer
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_scope IS NULL OR p_scope NOT IN ('success_logout', 'failure_throttled') THEN
        RAISE EXCEPTION 'invalid retention scope';
    END IF;
    IF p_batch_index IS NULL OR p_batch_index < 0 OR p_batch_index >= 100 THEN
        RAISE EXCEPTION 'invalid retention batch index';
    END IF;
    IF p_run_id IS NULL THEN
        RAISE EXCEPTION 'retention run id is required';
    END IF;
    IF p_cutoff IS NULL OR p_cutoff > now() THEN
        RAISE EXCEPTION 'retention cutoff must be in the past';
    END IF;
    IF p_scope = 'success_logout' THEN
        IF p_cutoff > now() - interval '90 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the success policy';
        END IF;
    ELSE
        IF p_cutoff > now() - interval '180 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the failure policy';
        END IF;
    END IF;

    INSERT INTO public.security_event_retention_runs
        (run_id, batch_index, scope, cutoff, deleted_count, status,
         executed_by, started_at, finished_at)
    VALUES
        (p_run_id::text, p_batch_index, p_scope, p_cutoff, 0, 'started',
         session_user::name, clock_timestamp(), NULL);
END;
$$;
"""


_ABANDON_FUNCTION = """
CREATE OR REPLACE FUNCTION public.abandon_retention_run(
    p_run_id uuid,
    p_batch_index integer,
    p_error_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_status text;
    v_executed_by name;
BEGIN
    IF p_run_id IS NULL THEN
        RAISE EXCEPTION 'retention run id is required';
    END IF;
    IF p_batch_index IS NULL OR p_batch_index < 0 OR p_batch_index >= 100 THEN
        RAISE EXCEPTION 'invalid retention batch index';
    END IF;
    IF p_error_code IS NULL
       OR p_error_code NOT IN (
           'DBAPIError', 'IntegrityError', 'OperationalError',
           'RuntimeError', 'SQLAlchemyError', 'UnknownError'
       ) THEN
        RAISE EXCEPTION 'invalid retention error code';
    END IF;

    SELECT status, executed_by
      INTO v_status, v_executed_by
      FROM public.security_event_retention_runs
     WHERE run_id = p_run_id::text
       AND batch_index = p_batch_index
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'retention run has not been started';
    END IF;
    IF v_executed_by IS DISTINCT FROM session_user THEN
        RAISE EXCEPTION 'retention run belongs to a different principal';
    END IF;
    IF v_status IS DISTINCT FROM 'started' THEN
        RAISE EXCEPTION 'retention run is not in started state';
    END IF;

    UPDATE public.security_event_retention_runs
       SET status = 'failed',
           deleted_count = 0,
           error_code = p_error_code,
           finished_at = clock_timestamp()
     WHERE run_id = p_run_id::text
       AND batch_index = p_batch_index
       AND status = 'started'
       AND executed_by = session_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'retention run state changed';
    END IF;
END;
$$;
"""


_PRUNE_FUNCTION = """
CREATE OR REPLACE FUNCTION public.prune_security_events(
    p_scope text,
    p_cutoff timestamp with time zone,
    p_batch_size integer,
    p_run_id uuid,
    p_batch_index integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_deleted integer;
    v_event_types text[];
    v_status text;
    v_executed_by name;
    v_run_scope text;
    v_run_cutoff timestamp with time zone;
BEGIN
    -- Parameter validation comes first so callers get the same deterministic
    -- scope/cutoff/batch diagnostics as before.
    IF p_scope IS NULL OR p_scope NOT IN ('success_logout', 'failure_throttled') THEN
        RAISE EXCEPTION 'invalid retention scope';
    END IF;
    IF p_batch_size IS NULL OR p_batch_size < 1 OR p_batch_size > 5000 THEN
        RAISE EXCEPTION 'invalid retention batch size';
    END IF;
    IF p_batch_index IS NULL OR p_batch_index < 0 OR p_batch_index >= 100 THEN
        RAISE EXCEPTION 'invalid retention batch index';
    END IF;
    IF p_cutoff IS NULL OR p_cutoff > now() THEN
        RAISE EXCEPTION 'retention cutoff must be in the past';
    END IF;
    IF p_scope = 'success_logout' THEN
        IF p_cutoff > now() - interval '90 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the success policy';
        END IF;
        v_event_types := ARRAY['auth.login_succeeded', 'auth.logout'];
    ELSE
        IF p_cutoff > now() - interval '180 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the failure policy';
        END IF;
        v_event_types := ARRAY['auth.login_failed', 'auth.login_throttled'];
    END IF;
    IF p_run_id IS NULL THEN
        RAISE EXCEPTION 'retention run id is required';
    END IF;

    -- Serialize prune and abandon on the same run row, then validate the
    -- ownership, current state, scope and cutoff inside this transaction.
    SELECT status, executed_by, scope, cutoff
      INTO v_status, v_executed_by, v_run_scope, v_run_cutoff
      FROM public.security_event_retention_runs
     WHERE run_id = p_run_id::text
       AND batch_index = p_batch_index
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'retention run has not been started';
    END IF;
    IF v_executed_by IS DISTINCT FROM session_user THEN
        RAISE EXCEPTION 'retention run belongs to a different principal';
    END IF;
    IF v_status IS DISTINCT FROM 'started' THEN
        RAISE EXCEPTION 'retention run is not in started state';
    END IF;
    IF v_run_scope IS DISTINCT FROM p_scope OR v_run_cutoff IS DISTINCT FROM p_cutoff THEN
        RAISE EXCEPTION 'retention run scope or cutoff mismatch';
    END IF;

    WITH candidates AS (
        SELECT se.id
        FROM public.security_events AS se
        WHERE se.event_type = ANY (v_event_types)
          AND se.created_at < p_cutoff
          AND pg_try_advisory_xact_lock(7381, se.id)
          AND NOT EXISTS (
              SELECT 1
              FROM public.security_event_retention_holds AS h
              WHERE h.security_event_id = se.id
                AND h.expires_at > now()
          )
        ORDER BY se.created_at, se.id
        LIMIT p_batch_size
    ),
    deleted AS (
        DELETE FROM public.security_events AS se
        USING candidates AS c
        WHERE se.id = c.id
        RETURNING se.id
    )
    SELECT count(*) INTO v_deleted FROM deleted;

    -- The success mark commits with the DELETE.  A rollback removes both.
    UPDATE public.security_event_retention_runs
       SET status = 'success',
           deleted_count = v_deleted,
           finished_at = clock_timestamp()
     WHERE run_id = p_run_id::text
       AND batch_index = p_batch_index
       AND status = 'started'
       AND executed_by = session_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'retention run state changed';
    END IF;

    RETURN v_deleted;
END;
$$;
"""


_HARDENED_PRUNE_FUNCTION = """
CREATE OR REPLACE FUNCTION public.prune_security_events(
    p_scope text,
    p_cutoff timestamp with time zone,
    p_batch_size integer,
    p_run_id uuid,
    p_batch_index integer
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_deleted integer;
    v_started timestamp with time zone := clock_timestamp();
    v_event_types text[];
BEGIN
    IF p_scope IS NULL OR p_scope NOT IN ('success_logout', 'failure_throttled') THEN
        RAISE EXCEPTION 'invalid retention scope';
    END IF;
    IF p_batch_size IS NULL OR p_batch_size < 1 OR p_batch_size > 5000 THEN
        RAISE EXCEPTION 'invalid retention batch size';
    END IF;
    IF p_batch_index IS NULL OR p_batch_index < 0 OR p_batch_index >= 100 THEN
        RAISE EXCEPTION 'invalid retention batch index';
    END IF;
    IF p_cutoff IS NULL OR p_cutoff > now() THEN
        RAISE EXCEPTION 'retention cutoff must be in the past';
    END IF;
    IF p_scope = 'success_logout' THEN
        IF p_cutoff > now() - interval '90 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the success policy';
        END IF;
        v_event_types := ARRAY['auth.login_succeeded', 'auth.logout'];
    ELSE
        IF p_cutoff > now() - interval '180 days' THEN
            RAISE EXCEPTION 'retention cutoff is newer than the failure policy';
        END IF;
        v_event_types := ARRAY['auth.login_failed', 'auth.login_throttled'];
    END IF;

    WITH candidates AS (
        SELECT se.id
        FROM public.security_events AS se
        WHERE se.event_type = ANY (v_event_types)
          AND se.created_at < p_cutoff
          AND pg_try_advisory_xact_lock(7381, se.id)
          AND NOT EXISTS (
              SELECT 1
              FROM public.security_event_retention_holds AS h
              WHERE h.security_event_id = se.id
                AND h.expires_at > now()
          )
        ORDER BY se.created_at, se.id
        LIMIT p_batch_size
    ),
    deleted AS (
        DELETE FROM public.security_events AS se
        USING candidates AS c
        WHERE se.id = c.id
        RETURNING se.id
    )
    SELECT count(*) INTO v_deleted FROM deleted;

    INSERT INTO public.security_event_retention_runs
        (run_id, batch_index, scope, cutoff, deleted_count, status,
         started_at, finished_at)
    VALUES
        (p_run_id::text, p_batch_index, p_scope, p_cutoff, v_deleted,
         'success', v_started, clock_timestamp());

    RETURN v_deleted;
END;
$$;
"""


def _duplicate_batches() -> list[tuple[str, int, int]]:
    connection = op.get_bind()
    return [
        (row[0], row[1], row[2])
        for row in connection.execute(
            sa.text(
                "SELECT run_id, batch_index, count(*) "
                "FROM public.security_event_retention_runs "
                "GROUP BY run_id, batch_index "
                "HAVING count(*) > 1 "
                "ORDER BY run_id, batch_index "
                "LIMIT 20"
            )
        ).all()
    ]


def upgrade() -> None:
    duplicates = _duplicate_batches()
    if duplicates:
        raise RuntimeError(
            "Refusing to add UNIQUE (run_id, batch_index) while duplicate "
            "retention run-log rows exist. Reconcile them manually first: "
            f"{duplicates}"
        )

    op.add_column(
        "security_event_retention_runs",
        sa.Column("executed_by", sa.String(length=63), nullable=True),
    )
    op.execute(
        "UPDATE public.security_event_retention_runs "
        "SET executed_by = 'legacy' WHERE executed_by IS NULL"
    )
    op.alter_column(
        "security_event_retention_runs",
        "executed_by",
        existing_type=sa.String(length=63),
        nullable=False,
    )

    op.drop_constraint(
        "security_event_retention_run_status_valid",
        "security_event_retention_runs",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_retention_run_status_valid",
        "security_event_retention_runs",
        "status IN ('started', 'success', 'partial', 'failed')",
    )
    op.create_unique_constraint(
        "security_event_retention_run_batch_unique",
        "security_event_retention_runs",
        ["run_id", "batch_index"],
    )

    op.execute(_BEGIN_FUNCTION)
    op.execute(_ABANDON_FUNCTION)
    op.execute(_PRUNE_FUNCTION)

    for signature in (
        "public.begin_retention_run(text, timestamptz, uuid, integer)",
        "public.abandon_retention_run(uuid, integer, text)",
        "public.prune_security_events(text, timestamptz, integer, uuid, integer)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")

    # Apply role-dependent state only when the provisioning roles already
    # exist.  A fresh install provisions them after migrations.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                WHERE rolname = 'utop14_retention_owner'
            ) THEN
                EXECUTE 'ALTER FUNCTION public.begin_retention_run(text, timestamptz, uuid, integer) OWNER TO utop14_retention_owner';
                EXECUTE 'ALTER FUNCTION public.abandon_retention_run(uuid, integer, text) OWNER TO utop14_retention_owner';
                EXECUTE 'ALTER FUNCTION public.prune_security_events(text, timestamptz, integer, uuid, integer) OWNER TO utop14_retention_owner';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles
                WHERE rolname = 'utop14_retention_runner'
            ) THEN
                EXECUTE 'GRANT EXECUTE ON FUNCTION public.begin_retention_run(text, timestamptz, uuid, integer) TO utop14_retention_runner';
                EXECUTE 'GRANT EXECUTE ON FUNCTION public.abandon_retention_run(uuid, integer, text) TO utop14_retention_runner';
                EXECUTE 'GRANT EXECUTE ON FUNCTION public.prune_security_events(text, timestamptz, integer, uuid, integer) TO utop14_retention_runner';
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    connection = op.get_bind()
    run_count = connection.execute(
        sa.text("SELECT count(*) FROM public.security_event_retention_runs")
    ).scalar_one()
    if run_count:
        raise RuntimeError(
            "Refusing to downgrade retention run-log integrity while run history "
            "exists; export it and restore from backup instead of a destructive "
            "downgrade."
        )

    op.execute("DROP FUNCTION IF EXISTS public.begin_retention_run(text, timestamptz, uuid, integer)")
    op.execute("DROP FUNCTION IF EXISTS public.abandon_retention_run(uuid, integer, text)")
    op.execute(_HARDENED_PRUNE_FUNCTION)

    op.drop_constraint(
        "security_event_retention_run_batch_unique",
        "security_event_retention_runs",
        type_="unique",
    )
    op.drop_constraint(
        "security_event_retention_run_status_valid",
        "security_event_retention_runs",
        type_="check",
    )
    op.create_check_constraint(
        "security_event_retention_run_status_valid",
        "security_event_retention_runs",
        "status IN ('success', 'partial', 'failed')",
    )
    op.drop_column("security_event_retention_runs", "executed_by")

    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.prune_security_events(text, timestamptz, integer, uuid, integer) "
        "FROM PUBLIC"
    )
