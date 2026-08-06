"""Add target, tags, scan_count, last_scanned_at to assets

Revision ID: 003_add_asset_target_tags
Revises: 006_scan_reference
Create Date: 2026-07-27

"""
from alembic import op
import sqlalchemy as sa

revision = '003_add_asset_target_tags'
down_revision = '006_scan_reference'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('assets') as batch_op:
        batch_op.add_column(sa.Column('target', sa.String(512), nullable=True))
        batch_op.add_column(sa.Column('tags', sa.Text(), nullable=True, server_default=''))
        batch_op.add_column(sa.Column('scan_count', sa.Integer(), nullable=True, server_default='0'))
        batch_op.add_column(sa.Column('last_scanned_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index('idx_assets_target', ['target'])


def downgrade():
    with op.batch_alter_table('assets') as batch_op:
        batch_op.drop_index('idx_assets_target')
        batch_op.drop_column('last_scanned_at')
        batch_op.drop_column('scan_count')
        batch_op.drop_column('tags')
        batch_op.drop_column('target')
