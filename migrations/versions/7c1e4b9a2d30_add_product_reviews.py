"""add product reviews

Revision ID: 7c1e4b9a2d30
Revises: 2f863a992991
Create Date: 2026-11-04 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c1e4b9a2d30'
down_revision = '2f863a992991'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'product_reviews',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('product_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('order_item_id', sa.Integer(), nullable=False),
        sa.Column('rating', sa.Integer(), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column(
            'status',
            sa.String(length=20),
            server_default=sa.text("'published'"),
            nullable=False,
        ),
        sa.Column('moderated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('moderated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('moderation_reason', sa.String(length=500), nullable=True),
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
            'rating BETWEEN 1 AND 5',
            name='product_review_rating_range',
        ),
        sa.CheckConstraint(
            'char_length(comment) BETWEEN 1 AND 2000',
            name='product_review_comment_length',
        ),
        sa.CheckConstraint(
            "status IN ('published', 'hidden')",
            name='product_review_status_valid',
        ),
        sa.CheckConstraint(
            "status <> 'hidden' OR moderation_reason IS NOT NULL",
            name='product_review_hidden_reason_present',
        ),
        sa.ForeignKeyConstraint(
            ['order_item_id'],
            ['order_items.id'],
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['product_id'],
            ['products.id'],
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['user_id'],
            ['users.id'],
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['moderated_by_user_id'],
            ['users.id'],
            ondelete='SET NULL',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'order_item_id',
            name='product_review_order_item_unique',
        ),
    )
    op.create_index(
        'ix_product_reviews_product_id_status_created_at',
        'product_reviews',
        ['product_id', 'status', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_product_reviews_user_id_created_at',
        'product_reviews',
        ['user_id', 'created_at'],
        unique=False,
    )
    op.create_index(
        'ix_product_reviews_status',
        'product_reviews',
        ['status'],
        unique=False,
    )
    op.create_index(
        'ix_product_reviews_rating',
        'product_reviews',
        ['rating'],
        unique=False,
    )
    op.create_index(
        'ix_product_reviews_created_at',
        'product_reviews',
        ['created_at'],
        unique=False,
    )


def downgrade():
    op.drop_index(
        'ix_product_reviews_created_at',
        table_name='product_reviews',
    )
    op.drop_index(
        'ix_product_reviews_rating',
        table_name='product_reviews',
    )
    op.drop_index(
        'ix_product_reviews_status',
        table_name='product_reviews',
    )
    op.drop_index(
        'ix_product_reviews_user_id_created_at',
        table_name='product_reviews',
    )
    op.drop_index(
        'ix_product_reviews_product_id_status_created_at',
        table_name='product_reviews',
    )
    op.drop_table('product_reviews')
