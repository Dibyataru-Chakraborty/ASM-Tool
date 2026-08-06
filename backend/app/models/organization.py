"""Multi-tenant organization and membership models."""

from sqlalchemy import Column, String, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class Organization(Base, TimestampMixin):
    """A customer tenant. All customer-owned ASM data is scoped to this ID."""

    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=get_uuid)
    code = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="active", index=True)
    created_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    memberships = relationship("OrganizationMembership", back_populates="organization", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="organization")

    __table_args__ = (
        Index("idx_organizations_status", "status"),
    )


class OrganizationMembership(Base, TimestampMixin):
    """Maps a normal platform user to one customer organization and tenant role."""

    __tablename__ = "organization_memberships"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(32), nullable=False, default="user", index=True)  # admin | user
    status = Column(String(32), nullable=False, default="active", index=True)
    created_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User", foreign_keys=[user_id], back_populates="organization_memberships")

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_organization_membership"),
        Index("idx_memberships_org_role", "organization_id", "role", "status"),
        Index("idx_memberships_user", "user_id", "status"),
    )


class OrganizationAuditLog(Base, TimestampMixin):
    """Tenant-aware audit trail for privileged and customer actions."""

    __tablename__ = "organization_audit_logs"

    id = Column(String(36), primary_key=True, default=get_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    actor_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(120), nullable=False, index=True)
    resource_type = Column(String(80), nullable=True)
    resource_id = Column(String(64), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        Index("idx_org_audit_org_created", "organization_id", "created_at"),
        Index("idx_org_audit_actor_created", "actor_user_id", "created_at"),
    )
