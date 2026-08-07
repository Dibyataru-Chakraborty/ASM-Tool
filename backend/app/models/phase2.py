"""
Phase 2 Models: Port scanning, service detection, OS detection, technology fingerprinting.
"""

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Index, Text, Float
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Port(Base, TimestampMixin):
    """Open port discovered on a subdomain."""
    __tablename__ = "ports"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)  # TCP, UDP
    status = Column(String(20), default="open")  # open, closed, filtered
    service_name = Column(String(100), nullable=True)  # HTTP, SSH, etc.
    last_checked = Column(String, nullable=True)
    
    services = relationship("Service", back_populates="port", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("idx_ports_subdomain_port", "subdomain_id", "port_number", unique=True),
        Index("idx_ports_status", "status"),
    )


class Service(Base, TimestampMixin):
    """Service running on a port."""
    __tablename__ = "services"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), nullable=False)
    service_name = Column(String(100), nullable=False)
    version = Column(String(100), nullable=True)
    product = Column(String(255), nullable=True)
    os_type = Column(String(50), nullable=True)  # Linux, Windows, etc.
    confidence = Column(Float, default=0.0)  # 0.0 - 1.0
    
    port = relationship("Port", back_populates="services")
    banners = relationship("Banner", back_populates="service", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("idx_services_port_id", "port_id"),
    )


class Banner(Base, TimestampMixin):
    """Banner/version information from service."""
    __tablename__ = "banners"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=False)
    raw_banner = Column(Text, nullable=False)
    parsed_version = Column(String(100), nullable=True)
    cpe = Column(String(255), nullable=True)  # Common Platform Enumeration
    
    service = relationship("Service", back_populates="banners")
    
    __table_args__ = (
        Index("idx_banners_service_id", "service_id"),
    )


class Technology(Base, TimestampMixin):
    """Technology detected on subdomain."""
    __tablename__ = "technologies"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    technology_name = Column(String(100), nullable=False)
    technology_type = Column(String(50), nullable=True)  # Web Framework, Server, etc.
    version = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)
    
    __table_args__ = (
        Index("idx_technologies_subdomain", "subdomain_id"),
    )


class OSDetection(Base, TimestampMixin):
    """OS detection results."""
    __tablename__ = "os_detections"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    os_name = Column(String(100), nullable=True)  # Linux, Windows, macOS
    os_version = Column(String(100), nullable=True)
    os_family = Column(String(50), nullable=True)
    confidence = Column(Float, default=0.0)
    detection_method = Column(String(50), nullable=True)  # TTL analysis, banner, etc.
    
    __table_args__ = (
        Index("idx_os_subdomain", "subdomain_id"),
    )


class Vulnerability(Base, TimestampMixin):
    """Phase 3: Vulnerability from CVE database."""
    __tablename__ = "vulnerabilities"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    cve_id = Column(String(50), nullable=True)
    service_id = Column(String(36), ForeignKey("services.id", ondelete="CASCADE"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=True)  # Critical, High, Medium, Low
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    published_date = Column(String, nullable=True)
    is_false_positive = Column(Boolean, default=False, nullable=False)
    
    __table_args__ = (
        Index("idx_vuln_cve", "cve_id"),
        Index("idx_vuln_service", "service_id"),
    )
