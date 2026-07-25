"""
Domain model for primary reconnaissance targets.
"""

from sqlalchemy import Column, String, Date, DateTime, Boolean, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Domain(Base, TimestampMixin):
    """A domain under reconnaissance."""

    __tablename__ = "domains"

    id = Column(String(36), primary_key=True, default=get_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    
    # Domain info
    domain = Column(String(255), nullable=False, index=True)
    tld = Column(String(10), nullable=True)  # .com, .org, etc.
    
    # WHOIS info
    registrar = Column(String(255), nullable=True)
    registrar_whois_server = Column(String(255), nullable=True)
    registrar_id = Column(String(255), nullable=True)
    whois_server = Column(String(255), nullable=True)
    
    # Registration dates
    created_date = Column(Date, nullable=True)
    expiration_date = Column(Date, nullable=True)
    updated_date = Column(Date, nullable=True)
    
    # Admin contact (GDPR: may not be public)
    admin_email = Column(String(255), nullable=True)
    admin_phone = Column(String(20), nullable=True)
    
    # Status
    is_vulnerable = Column(Boolean, default=False, index=True)
    is_active = Column(Boolean, default=True, index=True)
    
    # Scanning metadata
    last_scanned = Column(DateTime(timezone=True), nullable=True)
    scan_status = Column(String(50), default="not_scanned")  # not_scanned, scanning, completed, failed
    
    # Relations
    asset = relationship("Asset", back_populates="domains")
    subdomains = relationship("Subdomain", back_populates="domain", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="domain", cascade="all, delete-orphan")
    ssl_certificates = relationship("SSLCertificate", back_populates="domain", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_domains_asset_domain", "asset_id", "domain", unique=True),
        Index("idx_domains_tld", "tld"),
        Index("idx_domains_expiration", "expiration_date"),
    )

    def __repr__(self):
        return f"<Domain(id={self.id}, domain={self.domain})>"
