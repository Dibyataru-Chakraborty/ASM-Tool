"""add persistent recurring scan schedules

Revision ID: 007_scan_schedules
Revises: 006_scan_reference, 003_add_asset_target_tags
Create Date: 2026-07-29
"""

from alembic import op
import sqlalchemy as sa


revision = "007_scan_schedules"
down_revision = ("006_scan_reference", "003_add_asset_target_tags")
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False),
        sa.Column("scan_type", sa.String(length=50), nullable=False),
        sa.Column(
            "is_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "is_paused",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("authorization_confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "notify_on_completion",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("notify_email", sa.String(length=255), nullable=True),
        sa.Column("notification_status", sa.String(length=100), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_status", sa.String(length=50), nullable=True),
        sa.Column("last_scan_id", sa.String(length=36), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "run_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "fail_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scan_schedules_user", "scan_schedules", ["user_id"])
    op.create_index("idx_scan_schedules_asset", "scan_schedules", ["asset_id"])
    op.create_index(
        "idx_scan_schedules_due",
        "scan_schedules",
        ["is_enabled", "is_paused", "next_run_at"],
    )
    op.create_index(
        "ix_scan_schedules_created_at",
        "scan_schedules",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_schedules_created_at", table_name="scan_schedules")
    op.drop_index("idx_scan_schedules_due", table_name="scan_schedules")
    op.drop_index("idx_scan_schedules_asset", table_name="scan_schedules")
    op.drop_index("idx_scan_schedules_user", table_name="scan_schedules")
    op.drop_table("scan_schedules")
