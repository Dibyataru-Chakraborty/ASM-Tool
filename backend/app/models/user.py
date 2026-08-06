"""
User model with RBAC roles and authentication fields.
"""

from sqlalchemy import Column, String, Boolean, Index
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class User(Base, TimestampMixin):
    """User account for authentication and authorization."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=get_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    
    # Legacy role is retained for migration/backward compatibility. Tenant
    # permissions are determined by platform_role + organization_memberships.
    role = Column(String(50), nullable=False, default="viewer", index=True)
    platform_role = Column(
        String(32), nullable=False, default="member", index=True
    )  # super_admin | member

    # Account status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)

    # MFA (Phase 8)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)

    # Relations
    assets = relationship("Asset", back_populates="owner", foreign_keys="Asset.user_id")
    organization_memberships = relationship(
        "OrganizationMembership",
        foreign_keys="OrganizationMembership.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_users_email_active", "email", "is_active"),
        Index("idx_users_role", "role"),
        Index("idx_users_platform_role", "platform_role"),
    )

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"
