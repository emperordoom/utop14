"""add security events

Revision ID: 9b2d4e6f8a10
Revises: 3f7a2c9d1b64
Create Date: 2026-11-04 13:00:00.000000

Creates the append-only ``security_events`` table used for authentication
auditing.  This migration is additive and leaves the M13 ``audit_logs`` table,
its trigger and its data untouched.

The trigger rejects ordinary row-level UPDATE/DELETE.  It permits FK
``ON DELETE SET NULL`` and a direct privileged UPDATE that clears the nullable
actor/subject identity links; all other fields remain immutable under those
row-level rules.  It is not absolute immutability against table owners,
superusers, ``TRUNCATE``, or a compromised privileged account.

Downgrade warning: ``downgrade()`` drops the ``security_events`` table and all
security-event audit history it contains.  This is destructive and must never
be executed against production without an explicit, separately approved data
retention decision and backup.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = "9b2d4e6f8a10"
down_revision = "3f7a2c9d1b64"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("actor_email", sa.String(length=255), nullable=True),
        sa.Column("subject_user_id", sa.Integer(), nullable=True),
        sa.Column("subject_email", sa.String(length=255), nullable=True),
        sa.Column("identifier_hash", sa.String(length=64), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column(
            "user_agent",
            sa.String(length=512),
            server_default=sa.text("''"),
            nullable=False,
        ),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "event_type IN ('auth.login_succeeded', 'auth.login_failed', 'auth.logout')",
            name="security_event_type_valid",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure')",
            name="security_event_outcome_valid",
        ),
        sa.CheckConstraint(
            "(event_type = 'auth.login_succeeded' "
            "AND outcome = 'success' "
            "AND reason_code = 'authenticated') "
            "OR (event_type = 'auth.login_failed' "
            "AND outcome = 'failure' "
            "AND reason_code IN ('unknown_account', 'inactive_account', 'invalid_password')) "
            "OR (event_type = 'auth.logout' "
            "AND outcome = 'success' "
            "AND reason_code = 'user_requested')",
            name="security_event_reason_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(metadata) = 'object'",
            name="security_event_metadata_object",
        ),
        sa.CheckConstraint(
            "char_length(user_agent) <= 512",
            name="security_event_user_agent_length",
        ),
        sa.CheckConstraint(
            "request_id IS NULL OR char_length(request_id) <= 64",
            name="security_event_request_id_length",
        ),
        sa.CheckConstraint(
            "identifier_hash IS NULL OR char_length(identifier_hash) = 64",
            name="security_event_identifier_hash_length",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_security_events_actor_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["subject_user_id"],
            ["users.id"],
            name="fk_security_events_subject_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_events_created_at_id",
        "security_events",
        ["created_at", "id"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_event_type_created_at",
        "security_events",
        ["event_type", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_outcome_created_at",
        "security_events",
        ["outcome", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_actor_user_id_created_at",
        "security_events",
        ["actor_user_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_subject_user_id_created_at",
        "security_events",
        ["subject_user_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_events_identifier_hash_created_at",
        "security_events",
        ["identifier_hash", "created_at"],
        unique=False,
    )

    # Enforce append-only row mutations for the security-event history.  This
    # does not protect against superusers, the table owner disabling the
    # trigger, TRUNCATE, or a compromised privileged database account.
    op.execute(
        """
        CREATE FUNCTION security_events_reject_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'security_events is append-only';
            END IF;

            -- Foreign-key ON DELETE SET NULL issues an UPDATE.  This block
            -- permits clearing either nullable actor/subject FK to NULL,
            -- whether from a FK action or a direct privileged UPDATE; every
            -- other field stays immutable, including email snapshots and
            -- timestamps.
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
        CREATE TRIGGER security_events_append_only
        BEFORE UPDATE OR DELETE ON security_events
        FOR EACH ROW
        EXECUTE FUNCTION security_events_reject_mutation();
        """
    )


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS security_events_append_only ON security_events")
    op.execute("DROP FUNCTION IF EXISTS security_events_reject_mutation()")
    op.drop_index(
        "ix_security_events_identifier_hash_created_at",
        table_name="security_events",
    )
    op.drop_index(
        "ix_security_events_subject_user_id_created_at",
        table_name="security_events",
    )
    op.drop_index(
        "ix_security_events_actor_user_id_created_at",
        table_name="security_events",
    )
    op.drop_index(
        "ix_security_events_outcome_created_at",
        table_name="security_events",
    )
    op.drop_index(
        "ix_security_events_event_type_created_at",
        table_name="security_events",
    )
    op.drop_index("ix_security_events_created_at_id", table_name="security_events")
    op.drop_table("security_events")
