"""Provisioning and tenant-user management for the multi-tenant ASM platform."""

from __future__ import annotations
import json, re, secrets
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import Organization, OrganizationMembership, OrganizationAuditLog, User, Asset, DiscoveredAsset, Exposure
from app.security import PasswordUtils
from app.services.auth_service import AuthService
from app.exceptions import ConflictError, ValidationError


class OrganizationService:
    def __init__(self, db: Session): self.db = db

    @staticmethod
    def _code(name: str) -> str:
        base = re.sub(r"[^A-Z0-9]+", "-", name.upper()).strip("-")[:24] or "ORG"
        return f"{base}-{secrets.token_hex(3).upper()}"

    def _audit(self, actor_id, action, organization_id=None, resource_type=None, resource_id=None, details=None):
        self.db.add(OrganizationAuditLog(
            organization_id=organization_id, actor_user_id=actor_id, action=action,
            resource_type=resource_type, resource_id=resource_id,
            details_json=json.dumps(details or {}, default=str),
        ))

    def create_organization(self, *, actor_id: str, name: str, description: str|None, code: str|None,
                            admin_email: str, admin_password: str, admin_name: str|None) -> Organization:
        if not name.strip(): raise ValidationError("Organization name is required")
        code=(code or self._code(name)).strip().upper()
        if self.db.query(Organization).filter(Organization.code==code).first():
            raise ConflictError("Organization code already exists")
        if self.db.query(User).filter(func.lower(User.email)==admin_email.lower()).first():
            raise ConflictError("Admin email already exists")
        AuthService(self.db).validate_password_strength(admin_password)
        org=Organization(code=code,name=name.strip(),description=description,status="active",created_by_user_id=actor_id)
        self.db.add(org); self.db.flush()
        admin=User(email=admin_email.lower(),password_hash=PasswordUtils.hash_password(admin_password),
                   full_name=admin_name or admin_email.split('@')[0],role="admin",platform_role="member",
                   is_active=True,is_verified=True)
        self.db.add(admin); self.db.flush()
        self.db.add(OrganizationMembership(organization_id=org.id,user_id=admin.id,role="admin",status="active",created_by_user_id=actor_id))
        self._audit(actor_id,"organization.created",org.id,"organization",org.id,{"name":org.name,"admin_email":admin.email})
        self.db.commit(); self.db.refresh(org); return org

    def list_organizations(self):
        rows=self.db.query(Organization).order_by(Organization.created_at.desc()).all()
        result=[]
        for org in rows:
            admin=(self.db.query(User).join(OrganizationMembership,OrganizationMembership.user_id==User.id)
                   .filter(OrganizationMembership.organization_id==org.id,OrganizationMembership.role=="admin",OrganizationMembership.status=="active").first())
            result.append({"id":org.id,"code":org.code,"name":org.name,"description":org.description,"status":org.status,
                           "admin":({"id":admin.id,"email":admin.email,"full_name":admin.full_name} if admin else None),
                           "user_count":self.db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==org.id,OrganizationMembership.status=="active").count(),
                           "asset_count":self.db.query(DiscoveredAsset).filter(DiscoveredAsset.organization_id==org.id,DiscoveredAsset.status!="historical").count(),
                           "critical_exposures":self.db.query(Exposure).filter(Exposure.organization_id==org.id,func.lower(Exposure.severity)=="critical",Exposure.status.in_(["open","in_progress"])).count(),
                           "created_at":org.created_at})
        return result

    def assign_admin(self, *, actor_id: str, organization_id: str, email: str, password: str|None=None, full_name: str|None=None):
        org=self.db.query(Organization).filter(Organization.id==organization_id).first()
        if not org: raise ValidationError("Organization not found")
        user=self.db.query(User).filter(func.lower(User.email)==email.lower()).first()
        if user and user.platform_role=="super_admin": raise ValidationError("Super Admin cannot be assigned as tenant Admin")
        if not user:
            if not password: raise ValidationError("Password is required for a new Admin")
            AuthService(self.db).validate_password_strength(password)
            user=User(email=email.lower(),password_hash=PasswordUtils.hash_password(password),full_name=full_name or email.split('@')[0],
                      role="admin",platform_role="member",is_active=True,is_verified=True)
            self.db.add(user); self.db.flush()
        # Exact requested flow: one active Admin per organization.
        self.db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==org.id,OrganizationMembership.role=="admin").update({"role":"user"},synchronize_session=False)
        membership=self.db.query(OrganizationMembership).filter(OrganizationMembership.organization_id==org.id,OrganizationMembership.user_id==user.id).first()
        if membership:
            membership.role="admin"; membership.status="active"
        else:
            # Do not let a normal tenant account silently span organizations.
            other=self.db.query(OrganizationMembership).filter(OrganizationMembership.user_id==user.id,OrganizationMembership.status=="active").first()
            if other: raise ConflictError("This user already belongs to another organization")
            self.db.add(OrganizationMembership(organization_id=org.id,user_id=user.id,role="admin",status="active",created_by_user_id=actor_id))
        user.role="admin"; user.is_active=True
        self._audit(actor_id,"organization.admin_changed",org.id,"user",user.id,{"email":user.email})
        self.db.commit(); return user

    def create_user(self, *, actor_id: str, organization_id: str, email: str, password: str, full_name: str|None=None):
        if self.db.query(User).filter(func.lower(User.email)==email.lower()).first(): raise ConflictError("User email already exists")
        AuthService(self.db).validate_password_strength(password)
        user=User(email=email.lower(),password_hash=PasswordUtils.hash_password(password),full_name=full_name or email.split('@')[0],
                  role="viewer",platform_role="member",is_active=True,is_verified=True)
        self.db.add(user); self.db.flush()
        self.db.add(OrganizationMembership(organization_id=organization_id,user_id=user.id,role="user",status="active",created_by_user_id=actor_id))
        self._audit(actor_id,"organization.user_created",organization_id,"user",user.id,{"email":user.email})
        self.db.commit(); self.db.refresh(user); return user
