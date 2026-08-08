"""
Asset service for managing reconnaissance targets.
"""

from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models import Asset, Domain
from app.repositories.asset_repo import AssetRepository
from app.repositories.domain_repo import DomainRepository
from app.exceptions import NotFoundError, ConflictError, ValidationError
import logging

logger = logging.getLogger(__name__)


class AssetService:
    """Service for managing assets (organizations/targets)."""

    def __init__(self, db: Session):
        self.db = db
        self.asset_repo = AssetRepository(db)
        self.domain_repo = DomainRepository(db)

    def create_asset(
        self,
        user_id: str,
        name: str,
        description: Optional[str] = None,
        asset_type: str = "domain",
        tenant_id: Optional[str] = None,
    ) -> Asset:
        """Create a new asset."""
        # Validate input
        if not name or len(name.strip()) == 0:
            raise ValidationError("Asset name cannot be empty")

        # Check for duplicates
        if tenant_id:
            existing = self.asset_repo.get_by_tenant_and_name(tenant_id, name)
        else:
            existing = self.asset_repo.get_by_user_and_name(user_id, name)

        if existing:
            raise ConflictError(f"Asset '{name}' already exists")

        # Create asset
        try:
            asset = self.asset_repo.create({
                "user_id": user_id,
                "tenant_id": tenant_id,
                "name": name.strip(),
                "description": description,
                "asset_type": asset_type,
                "status": "active",
                "risk_score": 0,
            })
            logger.info(f"Asset created: {asset.id} for tenant {tenant_id} (user {user_id})")
            return asset
        except Exception as e:
            logger.error(f"Error creating asset: {str(e)}")
            raise

    def get_asset(self, asset_id: str, user_id: str, tenant_id: Optional[str] = None) -> Asset:
        """Get asset by ID (with ownership check)."""
        asset = self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise NotFoundError("Asset")

        # Verify ownership
        if tenant_id:
            if asset.tenant_id != tenant_id:
                raise ValidationError("Unauthorized access to asset")
        elif asset.user_id != user_id:
            raise ValidationError("Unauthorized access to asset")

        return asset

    def list_assets(self, user_id: str, skip: int = 0, limit: int = 10, tenant_id: Optional[str] = None) -> tuple[List[Asset], int]:
        """List all assets for a user or tenant."""
        if tenant_id:
            return self.asset_repo.get_by_tenant_id(tenant_id, skip, limit)
        return self.asset_repo.get_by_user_id(user_id, skip, limit)

    def list_active_assets(self, user_id: str, skip: int = 0, limit: int = 10, tenant_id: Optional[str] = None) -> tuple[List[Asset], int]:
        """List active assets for a user or tenant."""
        if tenant_id:
            return self.asset_repo.get_active_assets_by_tenant(tenant_id, skip, limit)
        return self.asset_repo.get_active_assets(user_id, skip, limit)

    def update_asset(
        self,
        asset_id: str,
        user_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Asset:
        """Update an asset."""
        asset = self.get_asset(asset_id, user_id)

        update_data = {}
        if name:
            update_data["name"] = name
        if description is not None:
            update_data["description"] = description
        if status:
            if status not in ["active", "archived", "monitoring"]:
                raise ValidationError("Invalid status value")
            update_data["status"] = status

        if not update_data:
            return asset

        try:
            asset = self.asset_repo.update(asset_id, update_data)
            logger.info(f"Asset updated: {asset_id}")
            return asset
        except Exception as e:
            logger.error(f"Error updating asset: {str(e)}")
            raise

    def delete_asset(self, asset_id: str, user_id: str) -> bool:
        """Delete an asset."""
        asset = self.get_asset(asset_id, user_id)

        try:
            # Delete related domains (cascade)
            self.asset_repo.delete(asset_id)
            logger.info(f"Asset deleted: {asset_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting asset: {str(e)}")
            raise

    def archive_asset(self, asset_id: str, user_id: str) -> Asset:
        """Archive an asset (soft delete)."""
        asset = self.get_asset(asset_id, user_id)
        try:
            asset = self.asset_repo.archive_asset(asset_id)
            logger.info(f"Asset archived: {asset_id}")
            return asset
        except Exception as e:
            logger.error(f"Error archiving asset: {str(e)}")
            raise

    def get_asset_stats(self, asset_id: str, user_id: str) -> Dict[str, Any]:
        """Get statistics for an asset."""
        asset = self.get_asset(asset_id, user_id)

        try:
            domains, _ = self.domain_repo.get_by_asset_id(asset_id)
            total_domains = len(domains)
            vulnerable_domains = len([d for d in domains if d.is_vulnerable])

            # Count subdomains
            total_subdomains = sum(len(d.subdomains) for d in domains)

            return {
                "asset_id": asset_id,
                "name": asset.name,
                "total_domains": total_domains,
                "vulnerable_domains": vulnerable_domains,
                "total_subdomains": total_subdomains,
                "risk_score": asset.risk_score,
                "status": asset.status,
                "last_scanned": asset.updated_at,
            }
        except Exception as e:
            logger.error(f"Error getting asset stats: {str(e)}")
            raise

    def calculate_risk_score(self, asset_id: str) -> int:
        """Calculate risk score based on vulnerabilities."""
        try:
            asset = self.asset_repo.get_by_id(asset_id)
            if not asset:
                return 0

            domains, _ = self.domain_repo.get_by_asset_id(asset_id)
            vulnerable_count = len([d for d in domains if d.is_vulnerable])
            
            # Simple scoring: 0-100 based on vulnerability ratio
            if not domains:
                score = 0
            else:
                score = min(100, (vulnerable_count / len(domains)) * 100)

            # Update asset risk score
            self.asset_repo.update_risk_score(asset_id, int(score))
            return int(score)
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 0
