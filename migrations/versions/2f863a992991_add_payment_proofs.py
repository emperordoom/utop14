"""add payment proofs

Revision ID: 2f863a992991
Revises: 1b0a971b10c6
Create Date: 2026-10-30 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2f863a992991'
down_revision = '1b0a971b10c6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'payment_proofs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('payment_id', sa.Integer(), nullable=False),
        sa.Column('proof_filename', sa.String(length=64), nullable=False),
        sa.Column('mime_type', sa.String(length=64), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column(
            'status',
            sa.String(length=20),
            server_default=sa.text("'pending_review'"),
            nullable=False,
        ),
        sa.Column(
            'submitted_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('reviewed_by_user_id', sa.Integer(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rejection_reason', sa.String(length=500), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending_review', 'approved', 'rejected', 'cancelled')",
            name='payment_proof_status_valid',
        ),
        sa.CheckConstraint('file_size > 0', name='payment_proof_file_size_positive'),
        sa.CheckConstraint(
            'file_size <= 5242880',
            name='payment_proof_file_size_limit',
        ),
        sa.CheckConstraint(
            "status <> 'rejected' OR rejection_reason IS NOT NULL",
            name='payment_proof_rejection_reason_present',
        ),
        sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(
            ['reviewed_by_user_id'],
            ['users.id'],
            ondelete='SET NULL',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('proof_filename'),
    )
    op.create_index(
        'ix_payment_proofs_payment_id_submitted_at',
        'payment_proofs',
        ['payment_id', 'submitted_at'],
        unique=False,
    )
    op.create_index(
        'ix_payment_proofs_status',
        'payment_proofs',
        ['status'],
        unique=False,
    )
    op.create_index(
        'uq_payment_proofs_one_pending_per_payment',
        'payment_proofs',
        ['payment_id'],
        unique=True,
        postgresql_where=sa.text("status = 'pending_review'"),
    )
    op.create_index(
        'uq_payment_proofs_one_approved_per_payment',
        'payment_proofs',
        ['payment_id'],
        unique=True,
        postgresql_where=sa.text("status = 'approved'"),
    )


def downgrade():
    op.drop_index('uq_payment_proofs_one_approved_per_payment', table_name='payment_proofs')
    op.drop_index('uq_payment_proofs_one_pending_per_payment', table_name='payment_proofs')
    op.drop_index('ix_payment_proofs_status', table_name='payment_proofs')
    op.drop_index('ix_payment_proofs_payment_id_submitted_at', table_name='payment_proofs')
    op.drop_table('payment_proofs')
