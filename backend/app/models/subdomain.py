"""
Subdomain model for discovered subdomains.
"""

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Index, DateTime, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Subdomain(Base, TimestampMixin):
    """A discovered subdomain."""

    __tablename__ = "subdomains"

    id = Column(String(36), primary_key=True, default=get_uuid)
    domain_id = Column(String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    
    # Subdomain name (e.g., "api.example.com")
    subdomain = Column(String(255), nullable=False, index=True)
    
    # Resolved IPs (stored as JSON string for Phase 1, proper array in Phase 2)
    ip_addresses = Column(Text, nullable=True)  # JSON array: ["1.2.3.4", "1.2.3.5"]
    
    # HTTP/HTTPS status
    is_responsive = Column(Boolean, default=False, index=True)
    response_status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    
    # SSL/TLS
    has_ssl = Column(Boolean, default=False)
    ssl_grade = Column(String(10), nullable=True)  # A+, A, B, C, etc.
    
    # Technology detection (Phase 2)
    technologies = Column(Text, nullable=True)  # JSON: ["nginx", "Node.js", ...]
    
    # Monitoring
    last_checked = Column(DateTime(timezone=True), nullable=True)
    is_monitored = Column(Boolean, default=False)
    
    # Relations
    domain = relationship("Domain", back_populates="subdomains")
    screenshots = relationship("Screenshot", back_populates="subdomain", cascade="all, delete-orphan")
    ssl_certificates = relationship("SSLCertificate", back_populates="subdomain", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_subdomains_domain_subdomain", "domain_id", "subdomain", unique=True),
        Index("idx_subdomains_responsive", "is_responsive"),
        Index("idx_subdomains_monitored", "is_monitored"),
    )

    def __repr__(self):
        return f"<Subdomain(id={self.id}, subdomain={self.subdomain})>"
