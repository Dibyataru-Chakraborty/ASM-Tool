"""
Asset repository with asset-specific operations.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from app.models import Asset
from app.repositories.base import BaseRepository
import logging

logger = logging.getLogger(__name__)


class AssetRepository(BaseRepository[Asset]):
    """Asset repository for organizational targets."""

    def __init__(self, db: Session):
        super().__init__(Asset, db)

    def get_by_user_id(self, user_id: str, skip: int = 0, limit: int = 100):
        """Get all assets for a user."""
        try:
            query = self.db.query(Asset).filter(Asset.user_id == user_id)
            total = query.count()
            assets = query.offset(skip).limit(limit).all()
            return assets, total
        except Exception as e:
            logger.error(f"Error fetching assets for user: {str(e)}")
            return [], 0

    def get_by_user_and_name(self, user_id: str, name: str) -> Optional[Asset]:
        """Get asset by user and name."""
        try:
            return self.db.query(Asset).filter(
                Asset.user_id == user_id,
                Asset.name == name
            ).first()
        except Exception as e:
            logger.error(f"Error fetching asset by name: {str(e)}")
            return None

    def get_active_assets(self, user_id: str, skip: int = 0, limit: int = 100):
        """Get active assets for user."""
        try:
            query = self.db.query(Asset).filter(
                Asset.user_id == user_id,
                Asset.status == "active"
            )
            total = query.count()
            assets = query.offset(skip).limit(limit).all()
            return assets, total
        except Exception as e:
            logger.error(f"Error fetching active assets: {str(e)}")
            return [], 0

    def get_by_type(self, user_id: str, asset_type: str):
        """Get assets by type."""
        try:
            query = self.db.query(Asset).filter(
                Asset.user_id == user_id,
                Asset.asset_type == asset_type
            )
            total = query.count()
            assets = query.all()
            return assets, total
        except Exception as e:
            logger.error(f"Error fetching assets by type: {str(e)}")
            return [], 0

    def get_by_risk_score_range(
        self,
        user_id: str,
        min_score: int = 0,
        max_score: int = 100
    ):
        """Get assets by risk score range."""
        try:
            query = self.db.query(Asset).filter(
                Asset.user_id == user_id,
                Asset.risk_score >= min_score,
                Asset.risk_score <= max_score
            )
            assets = query.all()
            return assets
        except Exception as e:
            logger.error(f"Error fetching assets by risk score: {str(e)}")
            return []

    def archive_asset(self, asset_id: str) -> Optional[Asset]:
        """Archive an asset."""
        return self.update(asset_id, {"status": "archived"})

    def update_risk_score(self, asset_id: str, score: int) -> Optional[Asset]:
        """Update asset risk score."""
        return self.update(asset_id, {"risk_score": score})

    def get_by_tenant_id(self, tenant_id: str, skip: int = 0, limit: int = 100):
        """Get all assets for a tenant."""
        try:
            query = self.db.query(Asset).filter(Asset.tenant_id == tenant_id)
            total = query.count()
            assets = query.offset(skip).limit(limit).all()
            return assets, total
        except Exception as e:
            logger.error(f"Error fetching assets for tenant: {str(e)}")
            return [], 0

    def get_active_assets_by_tenant(self, tenant_id: str, skip: int = 0, limit: int = 100):
        """Get active assets for a tenant."""
        try:
            query = self.db.query(Asset).filter(
                Asset.tenant_id == tenant_id,
                Asset.status == "active"
            )
            total = query.count()
            assets = query.offset(skip).limit(limit).all()
            return assets, total
        except Exception as e:
            logger.error(f"Error fetching active assets for tenant: {str(e)}")
            return [], 0

    def get_by_tenant_and_name(self, tenant_id: str, name: str) -> Optional[Asset]:
        """Get asset by tenant and name."""
        try:
            return self.db.query(Asset).filter(
                Asset.tenant_id == tenant_id,
                Asset.name == name
            ).first()
        except Exception as e:
            logger.error(f"Error fetching asset by tenant and name: {str(e)}")
            return None
