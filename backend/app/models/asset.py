"""
Asset model representing an organization/target for reconnaissance.
"""

from sqlalchemy import Column, String, Text, Integer, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Asset(Base, TimestampMixin):
    """An asset (organization/target) for reconnaissance."""

    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(
        String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Creator/legacy owner. Authorization never uses this column.
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    target = Column(String(512), nullable=True, index=True)
    tags = Column(Text, nullable=True, default="[]")

    # Asset classification
    asset_type = Column(
        String(50),
        nullable=False,
        default="domain",
        index=True
    )  # domain, ip, subnet, organization

    # Status
    status = Column(
        String(50),
        nullable=False,
        default="active",
        index=True
    )  # active, archived, monitoring

    # Risk scoring
    risk_score = Column(Integer, default=0, index=True)
    scan_count = Column(Integer, default=0)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    # Relations
    owner = relationship("User", back_populates="assets", foreign_keys=[user_id])
    organization = relationship("Organization", back_populates="assets")
    domains = relationship("Domain", back_populates="asset", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_assets_org_status", "organization_id", "status"),
        Index("idx_assets_user_status", "user_id", "status"),
        Index("idx_assets_risk_score", "risk_score"),
    )

    @property
    def is_active(self):
        return self.status == "active"

    def __repr__(self):
        return f"<Asset(id={self.id}, name={self.name}, target={self.target}, type={self.asset_type})>"
