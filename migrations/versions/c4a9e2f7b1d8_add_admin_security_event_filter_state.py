"""Add the server-side admin security-event filter state table.

Revision ID: c4a9e2f7b1d8
Revises: e3b9f1c7a2d4
Create Date: 2026-11-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c4a9e2f7b1d8"
down_revision = "e3b9f1c7a2d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_security_event_filter_states",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("admin_user_id", sa.Integer(), nullable=False),
        sa.Column(
            "filters",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_accessed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="admin_security_event_filter_state_expiry_valid",
        ),
        sa.ForeignKeyConstraint(
            ["admin_user_id"],
            ["users.id"],
            name="fk_admin_security_event_filter_states_admin_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("token_hash"),
    )
    op.create_index(
        "ix_admin_security_event_filter_states_admin_user_id",
        "admin_security_event_filter_states",
        ["admin_user_id"],
    )
    op.create_index(
        "ix_admin_security_event_filter_states_expires_at",
        "admin_security_event_filter_states",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_admin_security_event_filter_states_expires_at",
        table_name="admin_security_event_filter_states",
    )
    op.drop_index(
        "ix_admin_security_event_filter_states_admin_user_id",
        table_name="admin_security_event_filter_states",
    )
    op.drop_table("admin_security_event_filter_states")
