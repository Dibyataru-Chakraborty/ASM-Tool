"""
DNS Record model for DNS enumeration results.
"""

from sqlalchemy import Column, String, Integer, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class DNSRecord(Base, TimestampMixin):
    """A DNS record for a domain."""

    __tablename__ = "dns_records"

    id = Column(String(36), primary_key=True, default=get_uuid)
    domain_id = Column(String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    
    # Record type
    record_type = Column(
        String(10),
        nullable=False,
        index=True
    )  # A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA
    
    # Record value (may contain multiple values for some types)
    record_value = Column(Text, nullable=False)
    
    # TTL
    ttl = Column(Integer, nullable=True)
    
    # Priority (for MX, SRV records)
    priority = Column(Integer, nullable=True)
    
    # Weight (for SRV records)
    weight = Column(Integer, nullable=True)
    
    # Port (for SRV records)
    port = Column(Integer, nullable=True)
    
    # Relations
    domain = relationship("Domain", back_populates="dns_records")

    __table_args__ = (
        Index("idx_dns_records_domain_type", "domain_id", "record_type"),
    )

    def __repr__(self):
        return f"<DNSRecord(id={self.id}, type={self.record_type}, value={self.record_value[:50]})>"
