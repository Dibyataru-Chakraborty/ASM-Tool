"""Persistent recurring scan schedules."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.models.base import Base, TimestampMixin, get_uuid


class ScanSchedule(Base, TimestampMixin):
    """A user-owned cron schedule for an authorized asset."""

    __tablename__ = "scan_schedules"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_id = Column(
        String(36),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    cron_expression = Column(String(100), nullable=False)
    timezone = Column(String(64), nullable=False, default="UTC")
    scan_type = Column(String(50), nullable=False, default="scheduled_full")

    is_enabled = Column(Boolean, nullable=False, default=True)
    is_paused = Column(Boolean, nullable=False, default=False)
    authorization_confirmed_at = Column(DateTime(timezone=True), nullable=False)

    notify_on_completion = Column(Boolean, nullable=False, default=False)
    notify_email = Column(String(255), nullable=True)
    notification_status = Column(String(100), nullable=True)

    next_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String(50), nullable=True)
    last_scan_id = Column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_error = Column(Text, nullable=True)
    run_count = Column(Integer, nullable=False, default=0)
    fail_count = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("idx_scan_schedules_org", "organization_id"),
        Index("idx_scan_schedules_user", "user_id"),
        Index("idx_scan_schedules_asset", "asset_id"),
        Index(
            "idx_scan_schedules_due",
            "is_enabled",
            "is_paused",
            "next_run_at",
        ),
    )

