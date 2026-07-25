"""
User repository with user-specific query methods.
"""

from typing import Optional
from sqlalchemy.orm import Session
from app.models import User
from app.repositories.base import BaseRepository
import logging

logger = logging.getLogger(__name__)


class UserRepository(BaseRepository[User]):
    """User repository with user-specific operations."""

    def __init__(self, db: Session):
        super().__init__(User, db)

    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        try:
            return self.db.query(User).filter(User.email == email).first()
        except Exception as e:
            logger.error(f"Error fetching user by email: {str(e)}")
            return None

    def get_active_users(self, skip: int = 0, limit: int = 100):
        """Get all active users."""
        try:
            query = self.db.query(User).filter(User.is_active == True)
            total = query.count()
            users = query.offset(skip).limit(limit).all()
            return users, total
        except Exception as e:
            logger.error(f"Error fetching active users: {str(e)}")
            return [], 0

    def get_by_role(self, role: str, skip: int = 0, limit: int = 100):
        """Get users by role."""
        try:
            query = self.db.query(User).filter(User.role == role)
            total = query.count()
            users = query.offset(skip).limit(limit).all()
            return users, total
        except Exception as e:
            logger.error(f"Error fetching users by role: {str(e)}")
            return [], 0

    def activate_user(self, user_id: str) -> Optional[User]:
        """Activate a user."""
        return self.update(user_id, {"is_active": True})

    def deactivate_user(self, user_id: str) -> Optional[User]:
        """Deactivate a user."""
        return self.update(user_id, {"is_active": False})

    def verify_user(self, user_id: str) -> Optional[User]:
        """Mark user as verified."""
        return self.update(user_id, {"is_verified": True})

    def update_role(self, user_id: str, role: str) -> Optional[User]:
        """Update user role."""
        return self.update(user_id, {"role": role})

    def email_exists(self, email: str) -> bool:
        """Check if email exists."""
        try:
            return self.db.query(User).filter(User.email == email).first() is not None
        except Exception:
            return False
