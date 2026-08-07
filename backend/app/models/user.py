"""
User model with RBAC roles and authentication fields.
"""

from sqlalchemy import Column, String, Boolean, Index, ForeignKey
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class User(Base, TimestampMixin):
    """User account for authentication and authorization."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=get_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    
    # RBAC
    role = Column(
        String(50),
        nullable=False,
        default="analyst",
        index=True
    )  # admin, analyst, viewer

    # Account status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)

    # MFA (Phase 8)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True)

    # Relations
    assets = relationship("Asset", back_populates="owner", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_users_email_active", "email", "is_active"),
        Index("idx_users_role", "role"),
    )

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
