"""Super-Admin provisioning and tenant Admin user-management endpoints."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from app.dependencies import require_super_admin, require_org_admin, require_tenant_member
from app.models import Organization, OrganizationMembership, User
from app.services.organization_service import OrganizationService
from app.exceptions import ConflictError, ValidationError
from app.utils.database import get_db

super_router=APIRouter(prefix="/super-admin",tags=["super-admin"])
org_router=APIRouter(prefix="/organization",tags=["organization"])

class OrganizationCreate(BaseModel):
    name:str=Field(...,min_length=2,max_length=255); code:Optional[str]=Field(None,max_length=64); description:Optional[str]=None
    admin_email:EmailStr; admin_password:str=Field(...,min_length=12); admin_name:Optional[str]=None
class AdminAssign(BaseModel):
    email:EmailStr; password:Optional[str]=Field(None,min_length=12); full_name:Optional[str]=None
class OrgUpdate(BaseModel):
    name:Optional[str]=Field(None,min_length=2,max_length=255); description:Optional[str]=None; status:Optional[str]=Field(None,pattern="^(active|disabled)$")
class UserCreate(BaseModel):
    email:EmailStr; password:str=Field(...,min_length=12); full_name:Optional[str]=None
class UserStatus(BaseModel): is_active:bool

@super_router.get("/overview")
def super_overview(current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    orgs=OrganizationService(db).list_organizations()
    return {"organizations":len(orgs),"active_organizations":sum(o["status"]=="active" for o in orgs),
            "total_users":sum(o["user_count"] for o in orgs),"critical_exposures":sum(o["critical_exposures"] for o in orgs),"items":orgs}

@super_router.get("/organizations")
def organizations(current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    items=OrganizationService(db).list_organizations(); return {"items":items,"total":len(items)}

@super_router.post("/organizations",status_code=status.HTTP_201_CREATED)
def create_organization(req:OrganizationCreate,current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    try:
        org=OrganizationService(db).create_organization(actor_id=current_user.id,name=req.name,description=req.description,code=req.code,
            admin_email=str(req.admin_email),admin_password=req.admin_password,admin_name=req.admin_name)
        return {"id":org.id,"code":org.code,"name":org.name,"status":org.status}
    except ConflictError as e: raise HTTPException(409,detail=e.message)
    except ValidationError as e: raise HTTPException(422,detail=e.message)

@super_router.get("/organizations/{organization_id}")
def organization_detail(organization_id:str,current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    org=db.query(Organization).filter(Organization.id==organization_id).first()
    if not org: raise HTTPException(404,detail="Organization not found")
    members=(db.query(OrganizationMembership,User).join(User,User.id==OrganizationMembership.user_id)
             .filter(OrganizationMembership.organization_id==org.id).order_by(OrganizationMembership.role,User.email).all())
    return {"id":org.id,"code":org.code,"name":org.name,"description":org.description,"status":org.status,
            "members":[{"id":u.id,"email":u.email,"full_name":u.full_name,"role":m.role,"status":m.status,"is_active":u.is_active} for m,u in members]}

@super_router.patch("/organizations/{organization_id}")
def update_organization(organization_id:str,req:OrgUpdate,current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    org=db.query(Organization).filter(Organization.id==organization_id).first()
    if not org: raise HTTPException(404,detail="Organization not found")
    if req.name is not None: org.name=req.name
    if req.description is not None: org.description=req.description
    if req.status is not None: org.status=req.status
    db.commit(); return {"id":org.id,"name":org.name,"status":org.status}

@super_router.put("/organizations/{organization_id}/admin")
def assign_admin(organization_id:str,req:AdminAssign,current_user=Depends(require_super_admin()),db:Session=Depends(get_db)):
    try:
        u=OrganizationService(db).assign_admin(actor_id=current_user.id,organization_id=organization_id,email=str(req.email),password=req.password,full_name=req.full_name)
        return {"id":u.id,"email":u.email,"full_name":u.full_name,"role":"admin"}
    except ConflictError as e: raise HTTPException(409,detail=e.message)
    except ValidationError as e: raise HTTPException(422,detail=e.message)

@org_router.get("")
def current_organization(current_user=Depends(require_tenant_member()),db:Session=Depends(get_db)):
    org=db.query(Organization).filter(Organization.id==current_user.current_organization_id).first()
    return {"id":org.id,"code":org.code,"name":org.name,"description":org.description,"status":org.status,"role":current_user.organization_role or "super_admin"}

@org_router.get("/users")
def list_users(current_user=Depends(require_org_admin()),db:Session=Depends(get_db)):
    rows=(db.query(OrganizationMembership,User).join(User,User.id==OrganizationMembership.user_id)
          .filter(OrganizationMembership.organization_id==current_user.current_organization_id).order_by(OrganizationMembership.role,User.email).all())
    return {"items":[{"id":u.id,"email":u.email,"full_name":u.full_name,"role":m.role,"membership_status":m.status,"is_active":u.is_active,"created_at":u.created_at} for m,u in rows],"total":len(rows)}

@org_router.post("/users",status_code=status.HTTP_201_CREATED)
def create_user(req:UserCreate,current_user=Depends(require_org_admin()),db:Session=Depends(get_db)):
    try:
        u=OrganizationService(db).create_user(actor_id=current_user.id,organization_id=current_user.current_organization_id,email=str(req.email),password=req.password,full_name=req.full_name)
        return {"id":u.id,"email":u.email,"full_name":u.full_name,"role":"user","is_active":u.is_active}
    except ConflictError as e: raise HTTPException(409,detail=e.message)
    except ValidationError as e: raise HTTPException(422,detail=e.message)

@org_router.patch("/users/{user_id}/status")
def set_user_status(user_id:str,req:UserStatus,current_user=Depends(require_org_admin()),db:Session=Depends(get_db)):
    row=(db.query(OrganizationMembership,User).join(User,User.id==OrganizationMembership.user_id)
         .filter(OrganizationMembership.organization_id==current_user.current_organization_id,User.id==user_id).first())
    if not row: raise HTTPException(404,detail="User not found")
    membership,user=row
    if membership.role=="admin": raise HTTPException(400,detail="Organization Admin can only be changed by Super Admin")
    user.is_active=req.is_active; membership.status="active" if req.is_active else "disabled"; db.commit()
    return {"id":user.id,"is_active":user.is_active,"membership_status":membership.status}
