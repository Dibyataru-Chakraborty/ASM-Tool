"""
Screenshot model for capturing and storing screenshots of discovered subdomains.
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index, Text
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Screenshot(Base, TimestampMixin):
    """A screenshot of a discovered subdomain."""

    __tablename__ = "screenshots"

    id = Column(String(36), primary_key=True, default=get_uuid)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False)
    
    # URL that was screenshotted
    url = Column(String(512), nullable=False, index=True)
    protocol = Column(String(10), nullable=True)  # http, https
    port = Column(Integer, nullable=True)
    
    # File storage
    file_path = Column(String(512), nullable=True)  # S3 or local path in Phase 6
    file_size = Column(Integer, nullable=True)  # bytes
    
    # HTTP response
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    
    # Page metadata
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    technologies = Column(Text, nullable=True)  # JSON array of detected tech
    
    # Quality flags
    is_valid = Column(Integer, default=1)  # 0 = invalid/blank, 1 = valid
    hash = Column(String(64), nullable=True)  # Perceptual hash for similarity detection
    
    # Relations
    subdomain = relationship("Subdomain", back_populates="screenshots")

    __table_args__ = (
        Index("idx_screenshots_subdomain_id", "subdomain_id"),
        Index("idx_screenshots_url", "url"),
    )

    def __repr__(self):
        return f"<Screenshot(id={self.id}, url={self.url}, status={self.status_code})>"
