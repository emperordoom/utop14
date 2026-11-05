"""add security event retention holds, run log and maintenance function

Revision ID: d7c1a9e4b2f8
Revises: b4d8e2f7a1c9
Create Date: 2026-11-05 14:00:00.000000

Adds investigative holds and a bounded retention run log.  It also adds a
SECURITY DEFINER entry point whose owner is assigned to the dedicated
retention owner by the external provisioning script; the migration never
creates database roles.

The append-only trigger is extended only for DELETE operations executed by the
retention owner.  Application roles and all other roles continue to receive the
original append-only error.  Superusers and sufficiently privileged table
owners remain outside this database-level boundary.

Downgrade refuses to drop history when hold or run-log rows exist.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "d7c1a9e4b2f8"
down_revision = "b4d8e2f7a1c9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_event_retention_holds",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("security_event_id", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="security_event_retention_hold_expiry_valid",
        ),
        sa.ForeignKeyConstraint(
            ["security_event_id"],
            ["security_events.id"],
            name="fk_security_event_retention_holds_event",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "security_event_id",
            name="uq_security_event_retention_holds_event",
        ),
    )
    op.create_index(
        "ix_security_event_retention_holds_expires_at",
        "security_event_retention_holds",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "security_event_retention_runs",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("batch_index", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("cutoff", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "finished_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "scope IN ('success_logout', 'failure_throttled')",
            name="security_event_retention_run_scope_valid",
        ),
        sa.CheckConstraint(
            "status IN ('success', 'partial', 'failed')",
            name="security_event_retention_run_status_valid",
        ),
        sa.CheckConstraint(
            "deleted_count >= 0",
            name="security_event_retention_run_deleted_nonnegative",
        ),
        sa.CheckConstraint(
            "batch_index >= 0",
            name="security_event_retention_run_batch_nonnegative",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_event_retention_runs_run_id",
        "security_event_retention_runs",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        "ix_security_event_retention_runs_started_at",
        "security_event_retention_runs",
        ["started_at"],
        unique=False,
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.security_events_reject_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                -- The SECURITY DEFINER retention entry point executes as its
                -- owner.  A normal application role cannot become this role.
                IF current_user = 'utop14_retention_owner' THEN
                    RETURN OLD;
                END IF;
                RAISE EXCEPTION 'security_events is append-only';
            END IF;

            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.event_type IS DISTINCT FROM OLD.event_type
               OR NEW.outcome IS DISTINCT FROM OLD.outcome
               OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
               OR NEW.actor_email IS DISTINCT FROM OLD.actor_email
               OR NEW.subject_email IS DISTINCT FROM OLD.subject_email
               OR NEW.identifier_hash IS DISTINCT FROM OLD.identifier_hash
               OR NEW.ip_address IS DISTINCT FROM OLD.ip_address
               OR NEW.user_agent IS DISTINCT FROM OLD.user_agent
               OR NEW.request_id IS DISTINCT FROM OLD.request_id
               OR NEW.metadata IS DISTINCT FROM OLD.metadata
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
               OR (
                    NEW.actor_user_id IS NOT NULL
                    AND NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
               )
               OR (
                    NEW.subject_user_id IS NOT NULL
                    AND NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id
               )
            THEN
                RAISE EXCEPTION 'security_events is append-only';
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )

    op.execute(
        """
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
    )
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.prune_security_events(text, timestamptz, integer, uuid, integer) "
        "FROM PUBLIC"
    )


def downgrade():
    connection = op.get_bind()
    hold_count = connection.execute(
        sa.text("SELECT count(*) FROM security_event_retention_holds")
    ).scalar_one()
    run_count = connection.execute(
        sa.text("SELECT count(*) FROM security_event_retention_runs")
    ).scalar_one()
    if hold_count or run_count:
        raise RuntimeError(
            "Refusing to downgrade security-event retention while hold or run-log "
            "history exists; archive/export it first."
        )

    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.prune_security_events(text, timestamptz, integer, uuid, integer) "
        "FROM PUBLIC"
    )
    op.execute(
        "DROP FUNCTION public.prune_security_events("
        "text, timestamptz, integer, uuid, integer)"
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.security_events_reject_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'security_events is append-only';
            END IF;

            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.event_type IS DISTINCT FROM OLD.event_type
               OR NEW.outcome IS DISTINCT FROM OLD.outcome
               OR NEW.reason_code IS DISTINCT FROM OLD.reason_code
               OR NEW.actor_email IS DISTINCT FROM OLD.actor_email
               OR NEW.subject_email IS DISTINCT FROM OLD.subject_email
               OR NEW.identifier_hash IS DISTINCT FROM OLD.identifier_hash
               OR NEW.ip_address IS DISTINCT FROM OLD.ip_address
               OR NEW.user_agent IS DISTINCT FROM OLD.user_agent
               OR NEW.request_id IS DISTINCT FROM OLD.request_id
               OR NEW.metadata IS DISTINCT FROM OLD.metadata
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
               OR (
                    NEW.actor_user_id IS NOT NULL
                    AND NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
               )
               OR (
                    NEW.subject_user_id IS NOT NULL
                    AND NEW.subject_user_id IS DISTINCT FROM OLD.subject_user_id
               )
            THEN
                RAISE EXCEPTION 'security_events is append-only';
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )

    op.drop_index(
        "ix_security_event_retention_runs_started_at",
        table_name="security_event_retention_runs",
    )
    op.drop_index(
        "ix_security_event_retention_runs_run_id",
        table_name="security_event_retention_runs",
    )
    op.drop_table("security_event_retention_runs")
    op.drop_index(
        "ix_security_event_retention_holds_expires_at",
        table_name="security_event_retention_holds",
    )
    op.drop_table("security_event_retention_holds")
