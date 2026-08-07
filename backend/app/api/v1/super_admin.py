"""
Super Admin and Organization API routes.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
import uuid

from app.utils.database import get_db
from app.dependencies import get_current_user
from app.models import User, Tenant

super_admin_router = APIRouter(prefix="/super-admin", tags=["super-admin"])
organization_router = APIRouter(prefix="/organization", tags=["organization"])

# Schemas
class CreateOrgRequest(BaseModel):
    name: str
    description: Optional[str] = None
    admin_name: str
    admin_email: str
    admin_password: str

class UpdateOrgRequest(BaseModel):
    status: Optional[str] = None
    name: Optional[str] = None

class AssignAdminRequest(BaseModel):
    email: str
    full_name: Optional[str] = None
    password: Optional[str] = None

class CreateUserRequest(BaseModel):
    email: str
    full_name: Optional[str] = None
    password: str
    role: Optional[str] = "analyst"

class UpdateUserStatusRequest(BaseModel):
    is_active: bool


# ==========================================
# SUPER ADMIN ROUTES
# ==========================================

@super_admin_router.get("/overview")
async def get_overview(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get platform overview statistics and organizations list."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenants = db.query(Tenant).all()
    users = db.query(User).all()
    
    # Calculate statistics
    organizations_count = len(tenants)
    active_organizations_count = sum(1 for t in tenants if t.is_active)
    total_users_count = len(users)
    
    # Calculate critical exposures across all assets
    from app.models.phase2 import Vulnerability
    try:
        critical_exposures_count = db.query(Vulnerability).filter(Vulnerability.severity == "Critical").count()
    except Exception:
        critical_exposures_count = 0
        
    # Map tenants to items
    items = []
    for t in tenants:
        # Find admin user for this tenant
        tenant_admin = db.query(User).filter(User.tenant_id == t.id, User.role == "admin").first()
        if not tenant_admin:
            tenant_admin = db.query(User).filter(User.tenant_id == t.id).first()
            
        user_count = db.query(User).filter(User.tenant_id == t.id).count()
        
        # Calculate asset count
        from app.models.asset import Asset
        tenant_users = db.query(User).filter(User.tenant_id == t.id).all()
        tenant_user_ids = [u.id for u in tenant_users]
        
        asset_count = db.query(Asset).filter(Asset.user_id.in_(tenant_user_ids)).count() if tenant_user_ids else 0
        
        # Calculate critical exposures for this tenant
        critical_exp = 0
        if tenant_user_ids:
            try:
                from app.models.phase2 import Service, Port, Subdomain, Domain
                critical_exp = db.query(Vulnerability).join(Service).join(Port).join(Subdomain).join(Domain).join(Asset).filter(
                    Asset.user_id.in_(tenant_user_ids),
                    Vulnerability.severity == "Critical"
                ).count()
            except Exception:
                critical_exp = 0
                
        items.append({
            "id": t.id,
            "name": t.name,
            "status": "active" if t.is_active else "disabled",
            "admin": {
                "email": tenant_admin.email if tenant_admin else "Not assigned",
                "full_name": tenant_admin.full_name if tenant_admin else "Not assigned"
            },
            "user_count": user_count,
            "asset_count": asset_count,
            "critical_exposures": critical_exp
        })
        
    return {
        "organizations": organizations_count,
        "active_organizations": active_organizations_count,
        "total_users": total_users_count,
        "critical_exposures": critical_exposures_count,
        "items": items
    }


@super_admin_router.get("/organizations")
async def get_organizations(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all organizations (tenants)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenants = db.query(Tenant).all()
    result = []
    for t in tenants:
        tenant_admin = db.query(User).filter(User.tenant_id == t.id, User.role == "admin").first()
        result.append({
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "status": "active" if t.is_active else "disabled",
            "admin": {
                "email": tenant_admin.email if tenant_admin else "Not assigned",
                "full_name": tenant_admin.full_name if tenant_admin else "Not assigned"
            }
        })
    return result


@super_admin_router.post("/organizations")
async def create_organization(
    request: CreateOrgRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new organization and assign admin user."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    # Check if admin user email already exists
    existing_user = db.query(User).filter(User.email == request.admin_email.strip().lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Admin email is already registered")
        
    # Create tenant
    tenant_id = str(uuid.uuid4())
    slug = request.name.strip().lower().replace(" ", "-")
    existing_tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
    if existing_tenant:
        slug = f"{slug}-{str(uuid.uuid4())[:8]}"
        
    tenant = Tenant(
        id=tenant_id,
        name=request.name.strip(),
        slug=slug,
        is_active=True,
        subscription_tier="enterprise"
    )
    db.add(tenant)
    
    # Create admin user
    from app.security import PasswordUtils
    hashed_pw = PasswordUtils.hash_password(request.admin_password)
    admin_user = User(
        email=request.admin_email.strip().lower(),
        password_hash=hashed_pw,
        full_name=request.admin_name.strip(),
        role="admin",
        is_active=True,
        is_verified=True,
        tenant_id=tenant_id
    )
    db.add(admin_user)
    db.commit()
    
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "status": "active"
    }


@super_admin_router.get("/organizations/{id}")
async def get_organization(
    id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get organization by ID."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenant = db.query(Tenant).filter(Tenant.id == id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    tenant_admin = db.query(User).filter(User.tenant_id == tenant.id, User.role == "admin").first()
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "status": "active" if tenant.is_active else "disabled",
        "admin": {
            "email": tenant_admin.email if tenant_admin else "Not assigned",
            "full_name": tenant_admin.full_name if tenant_admin else "Not assigned"
        }
    }


@super_admin_router.patch("/organizations/{id}")
async def update_organization(
    id: str,
    request: UpdateOrgRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update organization status or details."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenant = db.query(Tenant).filter(Tenant.id == id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    if request.status is not None:
        tenant.is_active = (request.status == "active")
    if request.name is not None:
        tenant.name = request.name
        
    db.commit()
    return {
        "id": tenant.id,
        "name": tenant.name,
        "status": "active" if tenant.is_active else "disabled"
    }


@super_admin_router.put("/organizations/{id}/admin")
async def assign_organization_admin(
    id: str,
    request: AssignAdminRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Assign or update organization Admin."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenant = db.query(Tenant).filter(Tenant.id == id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    user = db.query(User).filter(User.email == request.email.strip().lower()).first()
    from app.security import PasswordUtils
    if user:
        user.tenant_id = tenant.id
        user.role = "admin"
        if request.full_name:
            user.full_name = request.full_name.strip()
        if request.password:
            user.password_hash = PasswordUtils.hash_password(request.password)
    else:
        if not request.password:
            raise HTTPException(status_code=400, detail="Password required for new user creation")
        user = User(
            email=request.email.strip().lower(),
            password_hash=PasswordUtils.hash_password(request.password),
            full_name=request.full_name.strip() if request.full_name else request.email.split("@")[0],
            role="admin",
            is_active=True,
            is_verified=True,
            tenant_id=tenant.id
        )
        db.add(user)
        
    db.commit()
    return {"message": "Admin assigned successfully"}


@super_admin_router.delete("/organizations/{id}")
async def delete_organization(
    id: str,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an organization and all its associated users, assets, and resources."""
    if current_user.role != "admin" or current_user.tenant_id is not None:
        raise HTTPException(status_code=403, detail="Super Admin role required")
        
    tenant = db.query(Tenant).filter(Tenant.id == id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    # Bypass RLS to clean up tenant resources
    from sqlalchemy import text
    try:
        db.execute(text("SET app.bypass_rls = 'true'"))
    except Exception:
        pass
        
    # Delete all users belonging to this tenant
    # (Cascading foreign keys will automatically delete all assets, domains, subdomains, scans, and vulnerabilities associated with these users)
    db.query(User).filter(User.tenant_id == tenant.id).delete(synchronize_session=False)
    
    # Delete the tenant itself
    db.delete(tenant)
    db.commit()
    
    return {"message": "Organization deleted successfully"}


# ==========================================
# ORGANIZATION ENDPOINTS
# ==========================================

@organization_router.get("")
async def get_current_organization(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get active organization details from X-Organization-ID header or user association."""
    org_id = request.headers.get("X-Organization-ID")
    # If no header, or user is not a super admin, default to user's associated tenant
    if not org_id or current_user.role != "admin":
        org_id = current_user.tenant_id
        
    if not org_id:
        # If user has no associated tenant, return a mock or fallback to the first active tenant
        first_tenant = db.query(Tenant).filter(Tenant.is_active == True).first()
        if first_tenant:
            org_id = first_tenant.id
        else:
            raise HTTPException(status_code=404, detail="No active organization found")
            
    tenant = db.query(Tenant).filter(Tenant.id == org_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    return {
        "id": tenant.id,
        "name": tenant.name,
        "slug": tenant.slug,
        "status": "active" if tenant.is_active else "disabled"
    }


@organization_router.get("/users")
async def get_organization_users(
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get users in active organization."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin":
        org_id = current_user.tenant_id
        
    if not org_id:
        return []
        
    users = db.query(User).filter(User.tenant_id == org_id).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "is_verified": u.is_verified
        }
        for u in users
    ]


@organization_router.post("/users")
async def create_organization_user(
    request_body: CreateUserRequest,
    request: Request,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new user in the active organization."""
    org_id = request.headers.get("X-Organization-ID")
    if not org_id or current_user.role != "admin":
        org_id = current_user.tenant_id
        
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization context required")
        
    existing_user = db.query(User).filter(User.email == request_body.email.strip().lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    from app.security import PasswordUtils
    hashed_pw = PasswordUtils.hash_password(request_body.password)
    new_user = User(
        email=request_body.email.strip().lower(),
        password_hash=hashed_pw,
        full_name=request_body.full_name.strip() if request_body.full_name else None,
        role=request_body.role or "analyst",
        is_active=True,
        is_verified=True,
        tenant_id=org_id
    )
    db.add(new_user)
    db.commit()
    return {
        "id": new_user.id,
        "email": new_user.email,
        "full_name": new_user.full_name,
        "role": new_user.role
    }


@organization_router.patch("/users/{user_id}/status")
async def set_user_status(
    user_id: str,
    request_body: UpdateUserStatusRequest,
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Activate or deactivate user."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Check permissions
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")
        
    target_user.is_active = request_body.is_active
    db.commit()
    return {"message": "User status updated"}
