"""
Authentication service with user registration and login.
"""

from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models import User
from app.repositories.user_repo import UserRepository
from app.security import PasswordUtils, JWTUtils, TokenResponse
from app.exceptions import AuthenticationError, ConflictError, ValidationError
import logging
import re

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication and user management."""

    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)

    def validate_password_strength(self, password: str) -> bool:
        """Validate password meets security requirements."""
        from app.config import settings

        if len(password) < settings.password_min_length:
            raise ValidationError(
                f"Password must be at least {settings.password_min_length} characters long"
            )

        if settings.password_require_uppercase and not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain at least one uppercase letter")

        if settings.password_require_numbers and not re.search(r"\d", password):
            raise ValidationError("Password must contain at least one number")

        if settings.password_require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise ValidationError("Password must contain at least one special character")

        return True

    def register(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new user."""
        # Validate email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValidationError("Invalid email format")

        # Check if user exists
        if self.user_repo.email_exists(email):
            raise ConflictError(f"User with email {email} already exists")

        # Validate password
        self.validate_password_strength(password)

        # Create user
        try:
            user = self.user_repo.create({
                "email": email,
                "password_hash": PasswordUtils.hash_password(password),
                "full_name": full_name or email.split("@")[0],
                "role": "analyst",  # Default role
                "is_active": True,
                "is_verified": False,
            })

            logger.info(f"New user registered: {user.email}")

            # Generate tokens
            access_token = JWTUtils.create_access_token(
                subject=user.id,
                additional_claims={"role": user.role}
            )

            return {
                "user_id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "access_token": access_token,
                "token_type": "bearer",
            }
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            raise

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate user and return tokens."""
        # Get user
        user = self.user_repo.get_by_email(email)
        if not user:
            logger.warning(f"Login attempt with non-existent email: {email}")
            raise AuthenticationError("Invalid email or password")

        # Check if active
        if not user.is_active:
            logger.warning(f"Login attempt with inactive user: {email}")
            raise AuthenticationError("User account is inactive")

        # Verify password
        if not PasswordUtils.verify_password(password, user.password_hash):
            logger.warning(f"Failed login attempt: {email}")
            raise AuthenticationError("Invalid email or password")

        # Generate tokens
        access_token = JWTUtils.create_access_token(
            subject=user.id,
            additional_claims={"role": user.role}
        )

        refresh_token = JWTUtils.create_refresh_token(subject=user.id)

        logger.info(f"User logged in: {user.email}")

        platform_role = "super_admin" if user.role == "admin" and getattr(user, "tenant_id", None) is None else user.role
        return {
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 30 * 60,  # 30 minutes
            "platform_role": platform_role,
            "organization_id": getattr(user, "tenant_id", None)
        }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """Generate new access token from refresh token."""
        try:
            payload = JWTUtils.decode_token(refresh_token)
            user_id = payload.get("sub")

            # Verify user still exists and is active
            user = self.user_repo.get_by_id(user_id)
            if not user or not user.is_active:
                raise AuthenticationError("Invalid refresh token")

            # Generate new access token
            new_access_token = JWTUtils.create_access_token(
                subject=user_id,
                additional_claims={"role": user.role}
            )

            logger.debug(f"Access token refreshed for user: {user_id}")

            return {
                "access_token": new_access_token,
                "token_type": "bearer",
            }
        except Exception as e:
            logger.warning(f"Token refresh failed: {str(e)}")
            raise AuthenticationError("Invalid or expired refresh token")

    def get_current_user(self, user_id: str) -> Optional[User]:
        """Get current user by ID."""
        user = self.user_repo.get_by_id(user_id)
        if user and user.is_active:
            return user
        return None

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise ValidationError("User not found")

        # Verify old password
        if not PasswordUtils.verify_password(old_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect")

        # Validate new password
        self.validate_password_strength(new_password)

        # Update password
        self.user_repo.update(user_id, {
            "password_hash": PasswordUtils.hash_password(new_password)
        })

        logger.info(f"Password changed for user: {user_id}")
        return True
