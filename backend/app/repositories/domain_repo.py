"""
Domain repository with domain-specific operations.
"""

from typing import Optional, List
from sqlalchemy.orm import Session
from app.models import Domain
from app.repositories.base import BaseRepository
import logging

logger = logging.getLogger(__name__)


class DomainRepository(BaseRepository[Domain]):
    """Domain repository for reconnaissance targets."""

    def __init__(self, db: Session):
        super().__init__(Domain, db)

    def get_by_asset_id(self, asset_id: str, skip: int = 0, limit: int = 100):
        """Get all domains for an asset."""
        try:
            query = self.db.query(Domain).filter(Domain.asset_id == asset_id)
            total = query.count()
            domains = query.offset(skip).limit(limit).all()
            return domains, total
        except Exception as e:
            logger.error(f"Error fetching domains for asset: {str(e)}")
            return [], 0

    def get_by_domain_name(self, asset_id: str, domain: str) -> Optional[Domain]:
        """Get domain by name."""
        try:
            return self.db.query(Domain).filter(
                Domain.asset_id == asset_id,
                Domain.domain == domain
            ).first()
        except Exception as e:
            logger.error(f"Error fetching domain: {str(e)}")
            return None

    def get_vulnerable_domains(self, asset_id: str):
        """Get vulnerable domains."""
        try:
            return self.db.query(Domain).filter(
                Domain.asset_id == asset_id,
                Domain.is_vulnerable == True
            ).all()
        except Exception as e:
            logger.error(f"Error fetching vulnerable domains: {str(e)}")
            return []

    def get_expiring_soon(self, days: int = 30) -> List[Domain]:
        """Get domains expiring soon."""
        from datetime import datetime, timedelta
        try:
            cutoff_date = datetime.utcnow().date() + timedelta(days=days)
            return self.db.query(Domain).filter(
                Domain.expiration_date <= cutoff_date,
                Domain.expiration_date >= datetime.utcnow().date()
            ).all()
        except Exception as e:
            logger.error(f"Error fetching expiring domains: {str(e)}")
            return []

    def mark_vulnerable(self, domain_id: str) -> Optional[Domain]:
        """Mark domain as vulnerable."""
        return self.update(domain_id, {"is_vulnerable": True})

    def mark_safe(self, domain_id: str) -> Optional[Domain]:
        """Mark domain as safe."""
        return self.update(domain_id, {"is_vulnerable": False})

    def update_scan_status(self, domain_id: str, status: str) -> Optional[Domain]:
        """Update domain scan status."""
        from datetime import datetime
        return self.update(domain_id, {
            "scan_status": status,
            "last_scanned": datetime.utcnow()
        })

    def domain_exists(self, asset_id: str, domain: str) -> bool:
        """Check if domain exists for asset."""
        try:
            return self.db.query(Domain).filter(
                Domain.asset_id == asset_id,
                Domain.domain == domain
            ).first() is not None
        except Exception:
            return False
