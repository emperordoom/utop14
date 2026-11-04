"""add audit logs

Revision ID: 3f7a2c9d1b64
Revises: 7c1e4b9a2d30
Create Date: 2026-11-04 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '3f7a2c9d1b64'
down_revision = '7c1e4b9a2d30'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('actor_id', sa.Integer(), nullable=True),
        sa.Column('actor_email', sa.String(length=255), nullable=False),
        sa.Column('target_user_id', sa.Integer(), nullable=True),
        sa.Column('target_email', sa.String(length=255), nullable=False),
        sa.Column('action', sa.String(length=40), nullable=False),
        sa.Column('before_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('after_data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('ip_address', postgresql.INET(), nullable=False),
        sa.Column(
            'user_agent',
            sa.String(length=512),
            server_default=sa.text("''"),
            nullable=False,
        ),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ("
            "'user.profile_updated', "
            "'user.role_changed', "
            "'user.activated', "
            "'user.deactivated'"
            ")",
            name='audit_log_action_valid',
        ),
        sa.CheckConstraint(
            "jsonb_typeof(before_data) = 'object'",
            name='audit_log_before_object',
        ),
        sa.CheckConstraint(
            "jsonb_typeof(after_data) = 'object'",
            name='audit_log_after_object',
        ),
        sa.CheckConstraint(
            'char_length(user_agent) <= 512',
            name='audit_log_user_agent_length',
        ),
        sa.CheckConstraint(
            "request_id IS NULL OR char_length(request_id) <= 64",
            name='audit_log_request_id_length',
        ),
        sa.ForeignKeyConstraint(
            ['actor_id'],
            ['users.id'],
            name='fk_audit_logs_actor_id_users',
            ondelete='SET NULL',
        ),
        sa.ForeignKeyConstraint(
            ['target_user_id'],
            ['users.id'],
            name='fk_audit_logs_target_user_id_users',
            ondelete='SET NULL',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_audit_logs_created_at_id',
        'audit_logs',
        ['created_at', 'id'],
        unique=False,
    )
    op.create_index(
        'ix_audit_logs_action_created_at',
        'audit_logs',
        ['action', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_audit_logs_actor_id_created_at',
        'audit_logs',
        ['actor_id', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_audit_logs_target_user_id_created_at',
        'audit_logs',
        ['target_user_id', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_audit_logs_request_id',
        'audit_logs',
        ['request_id'],
        unique=False,
    )

    # Application-level append-only is reinforced for row-level mutations.
    # This does not protect against superusers, table owners disabling the
    # trigger, TRUNCATE, or a compromised privileged database account.
    op.execute(
        """
        CREATE FUNCTION audit_logs_reject_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'audit_logs is append-only';
            END IF;

            -- Foreign-key ON DELETE SET NULL issues an UPDATE.  Permit only
            -- clearing actor_id/target_user_id; every historical field stays
            -- immutable, including both email snapshots and all timestamps.
            IF NEW.id IS DISTINCT FROM OLD.id
               OR NEW.actor_email IS DISTINCT FROM OLD.actor_email
               OR NEW.target_email IS DISTINCT FROM OLD.target_email
               OR NEW.action IS DISTINCT FROM OLD.action
               OR NEW.before_data IS DISTINCT FROM OLD.before_data
               OR NEW.after_data IS DISTINCT FROM OLD.after_data
               OR NEW.ip_address IS DISTINCT FROM OLD.ip_address
               OR NEW.user_agent IS DISTINCT FROM OLD.user_agent
               OR NEW.request_id IS DISTINCT FROM OLD.request_id
               OR NEW.created_at IS DISTINCT FROM OLD.created_at
               OR (
                    NEW.actor_id IS NOT NULL
                    AND NEW.actor_id IS DISTINCT FROM OLD.actor_id
               )
               OR (
                    NEW.target_user_id IS NOT NULL
                    AND NEW.target_user_id IS DISTINCT FROM OLD.target_user_id
               )
            THEN
                RAISE EXCEPTION 'audit_logs is append-only';
            END IF;

            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_logs_append_only
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW
        EXECUTE FUNCTION audit_logs_reject_mutation();
        """
    )


def downgrade():
    op.execute('DROP TRIGGER IF EXISTS audit_logs_append_only ON audit_logs')
    op.execute('DROP FUNCTION IF EXISTS audit_logs_reject_mutation()')
    op.drop_index('ix_audit_logs_request_id', table_name='audit_logs')
    op.drop_index(
        'ix_audit_logs_target_user_id_created_at',
        table_name='audit_logs',
    )
    op.drop_index(
        'ix_audit_logs_actor_id_created_at',
        table_name='audit_logs',
    )
    op.drop_index(
        'ix_audit_logs_action_created_at',
        table_name='audit_logs',
    )
    op.drop_index('ix_audit_logs_created_at_id', table_name='audit_logs')
    op.drop_table('audit_logs')
