"""
Scan model for tracking scan jobs and execution history.
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Scan(Base, TimestampMixin):
    """A scan job run against an asset."""

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=get_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    
    # Scan classification
    scan_type = Column(
        String(50),
        nullable=False,
        index=True
    )  # discovery, ssl, screenshot, dns, port_scan, tech_detect
    
    # Status tracking
    status = Column(
        String(50),
        nullable=False,
        default="pending",
        index=True
    )  # pending, running, completed, failed, cancelled
    
    # Execution timing
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Results summary
    discovered_count = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    
    # Celery task tracking
    celery_task_id = Column(String(255), nullable=True, unique=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Targeting
    target_domain = Column(String(255), nullable=True)
    target_ip = Column(String(50), nullable=True)
    
    # Relations
    asset = relationship("Asset", back_populates="scans")

    __table_args__ = (
        Index("idx_scans_asset_id", "asset_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_type", "scan_type"),
        Index("idx_scans_created_at", "created_at"),
    )

    def __repr__(self):
        return f"<Scan(id={self.id}, type={self.scan_type}, status={self.status})>"
