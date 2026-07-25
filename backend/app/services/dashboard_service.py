"""
Dashboard service for metrics and risk aggregation.
"""

from typing import Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Asset, Domain, Scan, User
from app.exceptions import NotFoundError
import logging

logger = logging.getLogger(__name__)


class DashboardService:
    """Service for aggregating dashboard metrics and risk data."""

    def __init__(self, db: Session):
        self.db = db

    def get_risk_summary(self, user_id: str) -> Dict[str, Any]:
        """Get risk dashboard summary for a user."""
        try:
            # Get all user assets
            assets = self.db.query(Asset).filter(Asset.user_id == user_id).all()
            active_assets = [a for a in assets if a.status == "active"]

            # Count domains
            total_domains = self.db.query(Domain).filter(
                Domain.asset_id.in_([a.id for a in active_assets])
            ).count()

            # Count vulnerable domains
            vulnerable_domains = self.db.query(Domain).filter(
                Domain.asset_id.in_([a.id for a in active_assets]),
                Domain.is_vulnerable == True
            ).count()

            # Count subdomains
            from app.models import Subdomain
            total_subdomains = self.db.query(Subdomain).join(Domain).filter(
                Domain.asset_id.in_([a.id for a in active_assets])
            ).count()

            # Calculate average risk score
            avg_risk_score = 0
            if active_assets:
                avg_risk_score = sum(a.risk_score for a in active_assets) / len(active_assets)

            # Risk distribution
            risk_distribution = self._calculate_risk_distribution(active_assets)

            return {
                "total_assets": len(active_assets),
                "total_domains": total_domains,
                "total_subdomains": total_subdomains,
                "vulnerable_domains": vulnerable_domains,
                "avg_risk_score": round(avg_risk_score, 2),
                "risk_distribution": risk_distribution,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            logger.error(f"Error getting risk summary: {str(e)}")
            raise

    def get_asset_timeline(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get asset activity timeline."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            scans = self.db.query(Scan).join(Asset).filter(
                Asset.user_id == user_id,
                Scan.created_at >= cutoff_date
            ).order_by(Scan.created_at.desc()).all()

            timeline = []
            for scan in scans:
                timeline.append({
                    "scan_id": scan.id,
                    "type": scan.scan_type,
                    "status": scan.status,
                    "timestamp": scan.created_at.isoformat(),
                    "discovered_count": scan.discovered_count,
                })

            return timeline
        except Exception as e:
            logger.error(f"Error getting asset timeline: {str(e)}")
            raise

    def get_top_vulnerable_domains(self, user_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top vulnerable domains."""
        try:
            assets = self.db.query(Asset).filter(Asset.user_id == user_id).all()
            vulnerable = self.db.query(Domain).filter(
                Domain.asset_id.in_([a.id for a in assets]),
                Domain.is_vulnerable == True
            ).limit(limit).all()

            return [
                {
                    "domain_id": d.id,
                    "domain": d.domain,
                    "risk_score": d.asset.risk_score if d.asset else 0,
                    "scan_status": d.scan_status,
                    "last_scanned": d.last_scanned.isoformat() if d.last_scanned else None,
                }
                for d in vulnerable
            ]
        except Exception as e:
            logger.error(f"Error getting vulnerable domains: {str(e)}")
            raise

    def get_scan_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get scan execution statistics."""
        try:
            assets = self.db.query(Asset).filter(Asset.user_id == user_id).all()
            all_scans = self.db.query(Scan).filter(
                Scan.asset_id.in_([a.id for a in assets])
            ).all()

            if not all_scans:
                return {
                    "total_scans": 0,
                    "completed": 0,
                    "failed": 0,
                    "pending": 0,
                    "running": 0,
                    "success_rate": 0.0,
                }

            statuses = {}
            for scan in all_scans:
                statuses[scan.status] = statuses.get(scan.status, 0) + 1

            return {
                "total_scans": len(all_scans),
                "completed": statuses.get("completed", 0),
                "failed": statuses.get("failed", 0),
                "pending": statuses.get("pending", 0),
                "running": statuses.get("running", 0),
                "success_rate": self._calculate_success_rate(all_scans),
            }
        except Exception as e:
            logger.error(f"Error getting scan statistics: {str(e)}")
            raise

    def get_domain_risk_heatmap(self, user_id: str) -> List[Dict[str, Any]]:
        """Get domain risk heatmap data."""
        try:
            assets = self.db.query(Asset).filter(Asset.user_id == user_id).all()
            domains = self.db.query(Domain).filter(
                Domain.asset_id.in_([a.id for a in assets])
            ).order_by(Domain.asset_id).all()

            heatmap = []
            for domain in domains:
                asset = self.db.query(Asset).filter(Asset.id == domain.asset_id).first()
                heatmap.append({
                    "domain": domain.domain,
                    "asset": asset.name if asset else "Unknown",
                    "risk_level": self._categorize_risk(asset.risk_score if asset else 0),
                    "risk_score": asset.risk_score if asset else 0,
                    "is_vulnerable": domain.is_vulnerable,
                    "subdomain_count": len(domain.subdomains),
                })

            return heatmap
        except Exception as e:
            logger.error(f"Error getting risk heatmap: {str(e)}")
            raise

    def _calculate_risk_distribution(self, assets: List[Asset]) -> Dict[str, int]:
        """Calculate risk distribution across assets."""
        distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for asset in assets:
            score = asset.risk_score
            if score >= 80:
                distribution["critical"] += 1
            elif score >= 60:
                distribution["high"] += 1
            elif score >= 40:
                distribution["medium"] += 1
            else:
                distribution["low"] += 1

        return distribution

    def _calculate_success_rate(self, scans: List[Scan]) -> float:
        """Calculate scan success rate."""
        if not scans:
            return 0.0
        
        completed = len([s for s in scans if s.status == "completed"])
        return round((completed / len(scans)) * 100, 2)

    def _categorize_risk(self, score: int) -> str:
        """Categorize risk score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
