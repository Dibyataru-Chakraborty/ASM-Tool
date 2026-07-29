"""
Asset service for managing reconnaissance targets.
"""

from typing import Optional, List, Dict, Any
import json
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
        target: str,
        description: Optional[str] = None,
        asset_type: str = "domain",
        tags: Optional[List[str]] = None,
    ) -> Asset:
        """Create a new asset."""
        # Validate input
        if not name or len(name.strip()) == 0:
            raise ValidationError("Asset name cannot be empty")
        if not target or len(target.strip()) == 0:
            raise ValidationError("Asset target cannot be empty")
        domain_name = self._domain_from_target(target)
        if asset_type in {"domain", "subdomain", "url", "web_application"} and not domain_name:
            raise ValidationError("Domain and URL assets require a valid hostname")

        # Check for duplicates
        existing = self.asset_repo.get_by_user_and_name(user_id, name)
        if existing:
            raise ConflictError(f"Asset '{name}' already exists for this user")

        # Create asset
        try:
            asset = self.asset_repo.create({
                "user_id": user_id,
                "name": name.strip(),
                "target": target.strip(),
                "description": description,
                "asset_type": asset_type,
                "tags": json.dumps(tags or []),
                "status": "active",
                "risk_score": 0,
            })
            if asset_type in {"domain", "subdomain", "url", "web_application"} and domain_name:
                self.domain_repo.create({
                    "asset_id": asset.id,
                    "domain": domain_name,
                    "is_active": True,
                    "is_vulnerable": False,
                    "scan_status": "not_scanned",
                })
            logger.info(f"Asset created: {asset.id} for user {user_id}")
            return asset
        except Exception as e:
            logger.error(f"Error creating asset: {str(e)}")
            raise

    def get_asset(self, asset_id: str, user_id: str) -> Asset:
        """Get asset by ID (with ownership check)."""
        asset = self.asset_repo.get_by_id(asset_id)
        if not asset:
            raise NotFoundError("Asset")

        # Verify ownership
        if asset.user_id != user_id:
            raise ValidationError("Unauthorized access to asset")

        return asset

    def list_assets(self, user_id: str, skip: int = 0, limit: int = 10) -> tuple[List[Asset], int]:
        """List all assets for a user."""
        return self.asset_repo.get_by_user_id(user_id, skip, limit)

    def list_active_assets(self, user_id: str, skip: int = 0, limit: int = 10) -> tuple[List[Asset], int]:
        """List active assets for a user."""
        return self.asset_repo.get_active_assets(user_id, skip, limit)

    def update_asset(
        self,
        asset_id: str,
        user_id: str,
        name: Optional[str] = None,
        target: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        asset_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Asset:
        """Update an asset."""
        asset = self.get_asset(asset_id, user_id)

        update_data = {}
        effective_target = target or asset.target or asset.name
        effective_type = asset_type or asset.asset_type
        if (
            effective_type in {"domain", "subdomain", "url", "web_application"}
            and not self._domain_from_target(effective_target)
        ):
            raise ValidationError("Domain and URL assets require a valid hostname")
        if name:
            update_data["name"] = name
        if target:
            update_data["target"] = target.strip()
        if description is not None:
            update_data["description"] = description
        if asset_type:
            update_data["asset_type"] = asset_type
        if tags is not None:
            update_data["tags"] = json.dumps(tags)
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

    @staticmethod
    def _domain_from_target(target: str) -> Optional[str]:
        """Return a hostname for domain/URL assets, or None for other targets."""
        from urllib.parse import urlparse

        value = (target or "").strip().lower()
        if not value:
            return None
        parsed = urlparse(value if "://" in value else f"//{value}")
        hostname = (parsed.hostname or "").rstrip(".")
        if not hostname:
            return None
        labels = hostname.split(".")
        if (
            len(labels) < 2
            or not labels[-1].isalpha()
            or len(labels[-1]) < 2
            or any(not label or len(label) > 63 for label in labels)
        ):
            return None
        return hostname

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
