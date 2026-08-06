"""FastAPI dependencies for authentication, tenant isolation and RBAC."""

from typing import Optional
from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.security import JWTUtils
from app.exceptions import AuthenticationError
import logging

logger = logging.getLogger(__name__)


async def get_current_user_id(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
    try:
        return JWTUtils.extract_user_id(token)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=exc.message)


async def get_current_user(
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
    authorization: Optional[str] = Header(None),
    x_organization_id: Optional[str] = Header(None, alias="X-Organization-ID"),
):
    """Return the authenticated user with a resolved tenant context.

    Normal members always resolve their organization from the membership table;
    an organization ID supplied by the browser is ignored. Super Admin may select
    an organization explicitly through X-Organization-ID to enter that tenant's
    workspace.
    """
    from app.models import User, Organization, OrganizationMembership

    user = db.query(User).filter(User.id == user_id, User.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    user.current_organization_id = None
    user.current_organization_name = None
    user.organization_role = None

    if user.platform_role == "super_admin":
        if x_organization_id:
            org = db.query(Organization).filter(
                Organization.id == x_organization_id,
                Organization.status == "active",
            ).first()
            if not org:
                raise HTTPException(status_code=404, detail="Organization not found")
            user.current_organization_id = org.id
            user.current_organization_name = org.name
            user.organization_role = "super_admin"
        return user

    membership = (
        db.query(OrganizationMembership, Organization)
        .join(Organization, Organization.id == OrganizationMembership.organization_id)
        .filter(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.status == "active",
            Organization.status == "active",
        )
        .order_by(OrganizationMembership.created_at.asc())
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="No active organization membership")
    membership_row, org = membership
    user.current_organization_id = org.id
    user.current_organization_name = org.name
    user.organization_role = membership_row.role
    return user


def require_super_admin():
    async def check(current_user=Depends(get_current_user)):
        if current_user.platform_role != "super_admin":
            raise HTTPException(status_code=403, detail="Super Admin access required")
        return current_user
    return check


def require_tenant_member():
    async def check(current_user=Depends(get_current_user)):
        if not current_user.current_organization_id:
            raise HTTPException(status_code=400, detail="Select an organization first")
        return current_user
    return check


def require_org_admin():
    async def check(current_user=Depends(get_current_user)):
        if current_user.platform_role == "super_admin":
            if not current_user.current_organization_id:
                raise HTTPException(status_code=400, detail="Select an organization first")
            return current_user
        if current_user.organization_role != "admin":
            raise HTTPException(status_code=403, detail="Organization Admin access required")
        return current_user
    return check


def require_role(*allowed_roles: str):
    """Compatibility helper. New code should use tenant-aware dependencies above."""
    async def check(current_user=Depends(get_current_user)):
        effective = "admin" if current_user.platform_role == "super_admin" else current_user.organization_role
        translated = {"analyst": "user", "viewer": "user", "admin": "admin"}
        allowed = {translated.get(r, r) for r in allowed_roles}
        if effective not in allowed and current_user.platform_role != "super_admin":
            raise HTTPException(status_code=403, detail="Insufficient role")
        return current_user
    return check


def require_admin(): return require_org_admin()
def require_analyst(): return require_tenant_member()


class ServiceContainer:
    def __init__(self, db: Session):
        self.db = db
        self._services = {}
    def get_service(self, service_class):
        if service_class not in self._services:
            self._services[service_class] = service_class(self.db)
        return self._services[service_class]


def get_service_container(db: Session = Depends(get_db)) -> ServiceContainer:
    return ServiceContainer(db)
