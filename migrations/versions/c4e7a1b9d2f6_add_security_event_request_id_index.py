"""add security event request id index

Revision ID: c4e7a1b9d2f6
Revises: 9b2d4e6f8a10
Create Date: 2026-11-04 14:00:00.000000

Adds a request-id index to ``security_events`` for incident correlation.  The
index is created non-concurrently, which is acceptable for a newly introduced
table; if this migration is applied after the table has accumulated production
traffic, schedule it in a maintenance window or create the index separately with
``CONCURRENTLY``.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "c4e7a1b9d2f6"
down_revision = "9b2d4e6f8a10"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_security_events_request_id",
        "security_events",
        ["request_id"],
        unique=False,
    )


def downgrade():
    op.drop_index(
        "ix_security_events_request_id",
        table_name="security_events",
    )
