"""
SSL Certificate model for SSL/TLS certificate discovery and analysis.
"""

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class SSLCertificate(Base, TimestampMixin):
    """An SSL/TLS certificate discovered on a domain/subdomain."""

    __tablename__ = "ssl_certificates"

    id = Column(String(36), primary_key=True, default=get_uuid)
    domain_id = Column(String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    subdomain_id = Column(
        String(36),
        ForeignKey("subdomains.id", ondelete="SET NULL"),
        nullable=True
    )
    
    # Certificate details
    certificate_subject = Column(String(255), nullable=False, index=True)
    certificate_subject_alt_names = Column(Text, nullable=True)  # JSON array of SANs
    issuer = Column(String(255), nullable=False)
    
    # Validity dates
    valid_from = Column(DateTime(timezone=True), nullable=False)
    valid_to = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Certificate fingerprint (SHA256)
    fingerprint_sha256 = Column(String(64), unique=True, nullable=True)
    fingerprint_sha1 = Column(String(40), nullable=True)
    
    # Status
    is_valid = Column(Boolean, default=True, index=True)
    is_expired = Column(Boolean, default=False, index=True)
    is_self_signed = Column(Boolean, default=False)
    
    # Trust status
    is_trusted = Column(Boolean, default=True)
    trust_error = Column(Text, nullable=True)
    
    # Certificate transparency logs
    is_in_ct_logs = Column(Boolean, nullable=True)
    
    # Grade (Phase 3)
    ssl_grade = Column(String(10), nullable=True)  # A+, A, B, C, etc.
    
    # Relations
    domain = relationship("Domain", back_populates="ssl_certificates")
    subdomain = relationship("Subdomain", back_populates="ssl_certificates")

    __table_args__ = (
        Index("idx_ssl_domain_id", "domain_id"),
        Index("idx_ssl_valid_to", "valid_to"),
        Index("idx_ssl_expired", "is_expired"),
    )

    def __repr__(self):
        return f"<SSLCertificate(id={self.id}, subject={self.certificate_subject}, issuer={self.issuer})>"
