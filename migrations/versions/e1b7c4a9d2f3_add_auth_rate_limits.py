"""add auth rate limit buckets

Revision ID: e1b7c4a9d2f3
Revises: c4e7a1b9d2f6
Create Date: 2026-11-05 10:00:00.000000

Creates the PostgreSQL shared store for fixed-window authentication rate
limiting.  Bucket values are addressed only by HMAC digests; raw emails, IP
addresses, usernames and credentials are never stored.

Downgrade removes the rate-limit table and all current bucket/cooldown state.
It does not affect security_events or audit_logs.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "e1b7c4a9d2f3"
down_revision = "c4e7a1b9d2f6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "auth_rate_limits",
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "window_start",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column(
            "blocked_until",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "scope IN ('ip', 'identifier', 'combined')",
            name="auth_rate_limit_scope_valid",
        ),
        sa.CheckConstraint(
            "failure_count >= 0",
            name="auth_rate_limit_failure_count_nonnegative",
        ),
        sa.CheckConstraint(
            "char_length(key_hash) = 64",
            name="auth_rate_limit_key_hash_length",
        ),
        sa.CheckConstraint(
            "blocked_until IS NULL OR blocked_until >= window_start",
            name="auth_rate_limit_block_after_window",
        ),
        sa.CheckConstraint(
            "updated_at >= window_start",
            name="auth_rate_limit_updated_after_window",
        ),
        sa.PrimaryKeyConstraint("scope", "key_hash"),
    )
    op.create_index(
        "ix_auth_rate_limits_updated_at",
        "auth_rate_limits",
        ["updated_at"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_auth_rate_limits_updated_at",
        table_name="auth_rate_limits",
    )
    op.drop_table("auth_rate_limits")
