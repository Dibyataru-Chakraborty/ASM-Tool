"""Persisted Gemini assessments for Nmap-detected service versions."""

from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)

from app.models.base import Base, TimestampMixin, get_uuid


class AIServiceAssessment(Base, TimestampMixin):
    """A structured, explicitly AI-generated service-version assessment."""

    __tablename__ = "ai_service_assessments"

    id = Column(String(36), primary_key=True, default=get_uuid)
    scan_id = Column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    service_id = Column(
        String(36),
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
    )

    provider = Column(String(30), nullable=False, default="gemini")
    model_name = Column(String(100), nullable=False)
    lifecycle_status = Column(String(20), nullable=False)  # current, outdated, unknown
    severity = Column(String(20), nullable=False)  # Critical, High, Medium, Low, Info
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    detected_version = Column(String(100), nullable=True)
    latest_version = Column(String(100), nullable=True)
    cves = Column(Text, nullable=False, default="[]")  # JSON array
    remediation = Column(Text, nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    evidence_urls = Column(Text, nullable=False, default="[]")  # JSON array

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "service_id",
            name="uq_ai_service_assessment_scan_service",
        ),
        Index("idx_ai_service_assessments_scan", "scan_id"),
        Index("idx_ai_service_assessments_service", "service_id"),
        Index("idx_ai_service_assessments_severity", "severity"),
    )
