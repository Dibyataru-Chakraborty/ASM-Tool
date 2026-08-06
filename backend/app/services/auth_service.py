"""Authentication service for the multi-tenant ASM platform."""

from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models import User, Organization, OrganizationMembership
from app.repositories.user_repo import UserRepository
from app.security import PasswordUtils, JWTUtils
from app.exceptions import AuthenticationError, ConflictError, ValidationError
import logging, re

logger = logging.getLogger(__name__)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)

    def validate_password_strength(self, password: str) -> bool:
        from app.config import settings
        if len(password) < settings.password_min_length:
            raise ValidationError(f"Password must be at least {settings.password_min_length} characters long")
        if settings.password_require_uppercase and not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain at least one uppercase letter")
        if settings.password_require_numbers and not re.search(r"\d", password):
            raise ValidationError("Password must contain at least one number")
        if settings.password_require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must contain at least one special character")
        return True

    def register(self, *args, **kwargs):
        raise ValidationError("Public registration is disabled. Super Admin creates organization Admins; organization Admins create Users.")

    def _access_context(self, user: User) -> dict[str, Any]:
        if user.platform_role == "super_admin":
            return {"platform_role": "super_admin", "organization_id": None, "organization_role": None, "organization_name": None}
        row = (
            self.db.query(OrganizationMembership, Organization)
            .join(Organization, Organization.id == OrganizationMembership.organization_id)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.status == "active",
                Organization.status == "active",
            )
            .order_by(OrganizationMembership.created_at.asc())
            .first()
        )
        if not row:
            raise AuthenticationError("No active organization membership")
        membership, org = row
        return {
            "platform_role": "member",
            "organization_id": org.id,
            "organization_role": membership.role,
            "organization_name": org.name,
        }

    def _tokens(self, user: User, context: dict[str, Any]) -> tuple[str, str]:
        claims = {
            "platform_role": context["platform_role"],
            "organization_id": context["organization_id"],
            "organization_role": context["organization_role"],
        }
        return (
            JWTUtils.create_access_token(subject=user.id, additional_claims=claims),
            JWTUtils.create_refresh_token(subject=user.id),
        )

    def login(self, email: str, password: str) -> Dict[str, Any]:
        user = self.user_repo.get_by_email(email)
        if not user or not user.is_active or not PasswordUtils.verify_password(password, user.password_hash):
            raise AuthenticationError("Invalid email or password")
        context = self._access_context(user)
        access_token, refresh_token = self._tokens(user, context)
        return {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": context["organization_role"] or context["platform_role"],
            **context,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 30 * 60,
        }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        payload = JWTUtils.decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid refresh token")
        user_id = payload.get("sub")
        user = self.user_repo.get_by_id(user_id)
        if not user or not user.is_active:
            raise AuthenticationError("User not found or inactive")
        context = self._access_context(user)
        access_token = JWTUtils.create_access_token(
            subject=user.id,
            additional_claims={
                "platform_role": context["platform_role"],
                "organization_id": context["organization_id"],
                "organization_role": context["organization_role"],
            },
        )
        return {"access_token": access_token, "token_type": "bearer"}

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        user = self.user_repo.get_by_id(user_id)
        if not user or not PasswordUtils.verify_password(old_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")
        self.validate_password_strength(new_password)
        user.password_hash = PasswordUtils.hash_password(new_password)
        self.db.commit()
        return True
