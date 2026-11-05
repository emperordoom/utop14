"""harden security-event retention holds and function validation

Revision ID: e3b9f1c7a2d4
Revises: d7c1a9e4b2f8
Create Date: 2026-11-05 18:30:00.000000

Remediation for M14.3.3.1 findings M14331-02, L-04 and L-05.

* Adds a BEFORE INSERT OR UPDATE trigger on
  ``security_event_retention_holds`` that takes the same per-event advisory
  lock namespace (7381) used by the retention cleanup function.  Direct table
  writes can no longer bypass the hold/cleanup serialization protocol.
* Locks both the old and new event id, in deterministic order, when an UPDATE
  moves a hold to another event.
* Rejects a direct UPDATE that expires or shortens an active hold, and caps
  hold duration at 3650 days.
* Adds explicit NULL-scope and batch-index upper-bound validation to
  ``public.prune_security_events``.

The migration is additive.  It does not delete hold or run-log data.

Ownership note: ``CREATE OR REPLACE FUNCTION`` preserves the existing function
owner.  On a fresh install the migration runs before role provisioning, while
the function is still owned by the DDL role.  If provisioning has already
transferred ``prune_security_events`` to ``utop14_retention_owner``, this
migration must be run by the DBA/superuser (or after temporarily transferring
ownership); a non-superuser DDL role cannot replace a function it does not own.
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "e3b9f1c7a2d4"
down_revision = "d7c1a9e4b2f8"
branch_labels = None
depends_on = None


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

_LEGACY_PRUNE_FUNCTION = """
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
    IF p_scope NOT IN ('success_logout', 'failure_throttled') THEN
        RAISE EXCEPTION 'invalid retention scope';
    END IF;
    IF p_batch_size IS NULL OR p_batch_size < 1 OR p_batch_size > 5000 THEN
        RAISE EXCEPTION 'invalid retention batch size';
    END IF;
    IF p_batch_index IS NULL OR p_batch_index < 0 THEN
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

_HOLD_LOCK_FUNCTION = """
CREATE OR REPLACE FUNCTION public.security_event_retention_holds_lock()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    v_first integer;
    v_second integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_advisory_xact_lock(7381, NEW.security_event_id);
        IF NEW.expires_at > NEW.created_at + interval '3650 days' THEN
            RAISE EXCEPTION 'hold expiry exceeds the maximum allowed duration';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.security_event_id IS DISTINCT FROM OLD.security_event_id THEN
        v_first := LEAST(OLD.security_event_id, NEW.security_event_id);
        v_second := GREATEST(OLD.security_event_id, NEW.security_event_id);
        PERFORM pg_advisory_xact_lock(7381, v_first);
        PERFORM pg_advisory_xact_lock(7381, v_second);
    ELSE
        PERFORM pg_advisory_xact_lock(7381, NEW.security_event_id);
    END IF;

    -- A legitimate service replacement updates an already-expired hold, where
    -- OLD.expires_at <= now().  The NEW.created_at >= OLD.expires_at condition
    -- lets that path through while rejecting a direct attempt to expire or
    -- shorten a still-active hold.
    IF OLD.expires_at > now()
       AND NEW.expires_at < OLD.expires_at
       AND NEW.created_at < OLD.expires_at THEN
        RAISE EXCEPTION 'active investigative holds cannot be expired or shortened';
    END IF;

    IF NEW.expires_at > NEW.created_at + interval '3650 days' THEN
        RAISE EXCEPTION 'hold expiry exceeds the maximum allowed duration';
    END IF;

    RETURN NEW;
END;
$$;
"""


def upgrade():
    op.execute(_HARDENED_PRUNE_FUNCTION)
    op.execute(_HOLD_LOCK_FUNCTION)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.prune_security_events(text, timestamptz, integer, uuid, integer) "
        "FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.security_event_retention_holds_lock() FROM PUBLIC"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS security_event_retention_holds_lock "
        "ON public.security_event_retention_holds"
    )
    op.execute(
        "CREATE TRIGGER security_event_retention_holds_lock "
        "BEFORE INSERT OR UPDATE ON public.security_event_retention_holds "
        "FOR EACH ROW EXECUTE FUNCTION "
        "public.security_event_retention_holds_lock()"
    )


def downgrade():
    op.execute(
        "DROP TRIGGER IF EXISTS security_event_retention_holds_lock "
        "ON public.security_event_retention_holds"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS public.security_event_retention_holds_lock()"
    )
    op.execute(_LEGACY_PRUNE_FUNCTION)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.prune_security_events(text, timestamptz, integer, uuid, integer) "
        "FROM PUBLIC"
    )
