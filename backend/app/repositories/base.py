"""
Base repository class with generic CRUD operations.
All specific repositories inherit from this.
"""

from typing import TypeVar, Generic, Type, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.base import Base
from app.exceptions import NotFoundError, DatabaseError
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Base)


class BaseRepository(Generic[T]):
    """Generic CRUD repository for any SQLAlchemy model."""

    def __init__(self, model: Type[T], db: Session):
        self.model = model
        self.db = db

    def create(self, obj_in: dict) -> T:
        """Create a new record."""
        try:
            db_obj = self.model(**obj_in)
            self.db.add(db_obj)
            self.db.commit()
            self.db.refresh(db_obj)
            logger.debug(f"Created {self.model.__name__}: {db_obj.id}")
            return db_obj
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to create {self.model.__name__}")

    def get_by_id(self, id: str) -> Optional[T]:
        """Get record by ID."""
        try:
            return self.db.query(self.model).filter(self.model.id == id).first()
        except Exception as e:
            logger.error(f"Error fetching {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to fetch {self.model.__name__}")

    def get_all(self, skip: int = 0, limit: int = 100) -> tuple[List[T], int]:
        """Get all records with pagination."""
        try:
            query = self.db.query(self.model)
            total = query.count()
            records = query.offset(skip).limit(limit).all()
            return records, total
        except Exception as e:
            logger.error(f"Error fetching {self.model.__name__} list: {str(e)}")
            raise DatabaseError(f"Failed to fetch {self.model.__name__} list")

    def update(self, id: str, obj_in: dict) -> T:
        """Update an existing record."""
        try:
            db_obj = self.get_by_id(id)
            if not db_obj:
                raise NotFoundError(self.model.__name__)

            for field, value in obj_in.items():
                setattr(db_obj, field, value)

            self.db.commit()
            self.db.refresh(db_obj)
            logger.debug(f"Updated {self.model.__name__}: {id}")
            return db_obj
        except NotFoundError:
            raise
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to update {self.model.__name__}")

    def delete(self, id: str) -> bool:
        """Delete a record."""
        try:
            db_obj = self.get_by_id(id)
            if not db_obj:
                raise NotFoundError(self.model.__name__)

            self.db.delete(db_obj)
            self.db.commit()
            logger.debug(f"Deleted {self.model.__name__}: {id}")
            return True
        except NotFoundError:
            raise
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting {self.model.__name__}: {str(e)}")
            raise DatabaseError(f"Failed to delete {self.model.__name__}")

    def exists(self, id: str) -> bool:
        """Check if record exists."""
        try:
            return self.db.query(self.model).filter(self.model.id == id).first() is not None
        except Exception as e:
            logger.error(f"Error checking existence: {str(e)}")
            return False

    def count(self) -> int:
        """Count total records."""
        try:
            return self.db.query(self.model).count()
        except Exception as e:
            logger.error(f"Error counting {self.model.__name__}: {str(e)}")
            return 0
