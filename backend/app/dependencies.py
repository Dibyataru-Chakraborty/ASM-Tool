"""
Dependency injection container for FastAPI.
Handles authentication, authorization, and service injection.
"""

from typing import Optional
from fastapi import Depends, HTTPException, Header, Request
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.security import JWTUtils
from app.exceptions import AuthenticationError, AuthorizationError
import logging

logger = logging.getLogger(__name__)


async def get_current_user_id(
    request: Request,
    authorization: Optional[str] = Header(None)
) -> str:
    """Extract and validate current user from JWT token (header or cookie)."""
    token = None
    if authorization:
        try:
            scheme, token = authorization.split()
            if scheme.lower() != "bearer":
                token = None
        except ValueError:
            pass

    if not token:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Missing authorization header or cookie")

    try:
        user_id = JWTUtils.extract_user_id(token)
        return user_id
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=e.message)


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user_id),
):
    """Get current user from database."""
    from app.models import User
    from sqlalchemy import text
    
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
        
    org_id = request.headers.get("X-Organization-ID")
    path = request.url.path
    logger.info(f"get_current_user lookup: user_id={user.id}, role={user.role}, tenant_id={user.tenant_id}, org_id={org_id}, path={path}")
        
    # If the user is a super admin, and they are accessing a specific organization
    # workspace (via X-Organization-ID header), impersonate that organization's admin user
    if user.role == "admin" and user.tenant_id is None:
        if org_id:
            # Do not impersonate for platform-level super admin or auth routes
            if not path.startswith("/api/v1/super-admin") and not path.startswith("/api/v1/auth"):
                org_admin = db.query(User).filter(User.tenant_id == org_id, User.role == "admin").first()
                if not org_admin:
                    org_admin = db.query(User).filter(User.tenant_id == org_id).first()
                if org_admin:
                    logger.info(f"Super Admin impersonating tenant user {org_admin.email} (Tenant ID: {org_id})")
                    db.execute(text("SET app.current_user_id = :user_id"), {"user_id": org_admin.id})
                    return org_admin
                else:
                    logger.info(f"Impersonation target tenant {org_id} has no users!")
    
    return user


def require_role(*allowed_roles: str):
    """Dependency for role-based access control."""
    async def check_role(
        current_user = Depends(get_current_user),
    ):
        if current_user.role not in allowed_roles:
            logger.warning(
                f"Access denied for user {current_user.id} with role {current_user.role}"
            )
            raise HTTPException(
                status_code=403,
                detail=f"Role {current_user.role} is not allowed to access this resource",
            )
        return current_user

    return check_role


def require_admin():
    """Dependency for admin-only endpoints."""
    return require_role("admin")


def require_analyst():
    """Dependency for analyst+ endpoints."""
    return require_role("admin", "analyst")


class ServiceContainer:
    """Service dependency injection container."""

    def __init__(self, db: Session):
        self.db = db
        self._services = {}

    def get_service(self, service_class):
        """Get or create a service instance."""
        if service_class not in self._services:
            self._services[service_class] = service_class(self.db)
        return self._services[service_class]


def get_service_container(db: Session = Depends(get_db)) -> ServiceContainer:
    """Dependency for getting service container."""
    return ServiceContainer(db)
