"""add public scan reference IDs

Revision ID: 006_scan_reference
Revises: 5d2055aa8cfd
Create Date: 2026-07-28
"""

from alembic import op
import sqlalchemy as sa


revision = "006_scan_reference"
down_revision = "5d2055aa8cfd"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("reference_id", sa.String(length=32), nullable=True),
    )

    # Backfill existing rows with a readable reference derived from their
    # creation date and UUID. New rows use the model's random generator.
    op.execute(
        """
        UPDATE scans
        SET reference_id =
            'SCN-' ||
            to_char(
                COALESCE(created_at, CURRENT_TIMESTAMP) AT TIME ZONE 'UTC',
                'YYYYMMDD'
            ) ||
            '-' ||
            upper(substr(replace(id, '-', ''), 1, 16))
        WHERE reference_id IS NULL
        """
    )

    op.alter_column(
        "scans",
        "reference_id",
        existing_type=sa.String(length=32),
        nullable=False,
    )
    op.create_index(
        "idx_scans_reference_id",
        "scans",
        ["reference_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("idx_scans_reference_id", table_name="scans")
    op.drop_column("scans", "reference_id")
