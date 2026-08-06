"""add persisted Gemini service-version assessments

Revision ID: 008_ai_service_assessments
Revises: 007_scan_schedules
Create Date: 2026-07-30
"""

from alembic import op
import sqlalchemy as sa


revision = "008_ai_service_assessments"
down_revision = "007_scan_schedules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_service_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column(
            "provider",
            sa.String(length=30),
            nullable=False,
            server_default="gemini",
        ),
        sa.Column("model_name", sa.String(length=100), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("detected_version", sa.String(length=100), nullable=True),
        sa.Column("latest_version", sa.String(length=100), nullable=True),
        sa.Column(
            "cves",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column(
            "confidence",
            sa.Float(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "evidence_urls",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'[]'"),
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
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id",
            "service_id",
            name="uq_ai_service_assessment_scan_service",
        ),
    )
    op.create_index(
        "idx_ai_service_assessments_scan",
        "ai_service_assessments",
        ["scan_id"],
    )
    op.create_index(
        "idx_ai_service_assessments_service",
        "ai_service_assessments",
        ["service_id"],
    )
    op.create_index(
        "idx_ai_service_assessments_severity",
        "ai_service_assessments",
        ["severity"],
    )
    op.create_index(
        "ix_ai_service_assessments_created_at",
        "ai_service_assessments",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ai_service_assessments_created_at",
        table_name="ai_service_assessments",
    )
    op.drop_index(
        "idx_ai_service_assessments_severity",
        table_name="ai_service_assessments",
    )
    op.drop_index(
        "idx_ai_service_assessments_service",
        table_name="ai_service_assessments",
    )
    op.drop_index(
        "idx_ai_service_assessments_scan",
        table_name="ai_service_assessments",
    )
    op.drop_table("ai_service_assessments")
