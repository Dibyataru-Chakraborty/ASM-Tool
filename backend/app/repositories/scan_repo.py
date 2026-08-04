"""
Scan repository for tracking scan jobs and execution history.
"""

from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models import Scan
from app.repositories.base import BaseRepository
import logging

logger = logging.getLogger(__name__)


class ScanRepository(BaseRepository[Scan]):
    """Scan repository for tracking reconnaissance jobs."""

    def __init__(self, db: Session):
        super().__init__(Scan, db)

    def get_by_asset_id(self, asset_id: str, skip: int = 0, limit: int = 100):
        """Get all scans for an asset."""
        try:
            query = self.db.query(Scan).filter(Scan.asset_id == asset_id).order_by(desc(Scan.created_at))
            total = query.count()
            scans = query.offset(skip).limit(limit).all()
            return scans, total
        except Exception as e:
            logger.error(f"Error fetching scans for asset: {str(e)}")
            return [], 0

    def get_by_scan_type(self, asset_id: str, scan_type: str):
        """Get scans by type."""
        try:
            return self.db.query(Scan).filter(
                Scan.asset_id == asset_id,
                Scan.scan_type == scan_type
            ).order_by(desc(Scan.created_at)).all()
        except Exception as e:
            logger.error(f"Error fetching scans by type: {str(e)}")
            return []

    def get_by_status(self, asset_id: str, status: str):
        """Get scans by status."""
        try:
            return self.db.query(Scan).filter(
                Scan.asset_id == asset_id,
                Scan.status == status
            ).all()
        except Exception as e:
            logger.error(f"Error fetching scans by status: {str(e)}")
            return []

    def get_pending_scans(self, limit: int = 100) -> List[Scan]:
        """Get all pending scans across all assets."""
        try:
            return self.db.query(Scan).filter(
                Scan.status == "pending"
            ).order_by(Scan.created_at).limit(limit).all()
        except Exception as e:
            logger.error(f"Error fetching pending scans: {str(e)}")
            return []

    def get_running_scans(self) -> List[Scan]:
        """Get all running scans."""
        try:
            return self.db.query(Scan).filter(Scan.status == "running").all()
        except Exception as e:
            logger.error(f"Error fetching running scans: {str(e)}")
            return []

    def get_failed_scans(self, max_retries_exceeded: bool = False):
        """Get failed scans."""
        try:
            query = self.db.query(Scan).filter(Scan.status == "failed")
            if max_retries_exceeded:
                query = query.filter(Scan.retry_count >= Scan.max_retries)
            return query.all()
        except Exception as e:
            logger.error(f"Error fetching failed scans: {str(e)}")
            return []

    def get_by_celery_task_id(self, task_id: str) -> Optional[Scan]:
        """Get scan by Celery task ID."""
        try:
            return self.db.query(Scan).filter(Scan.celery_task_id == task_id).first()
        except Exception as e:
            logger.error(f"Error fetching scan by task ID: {str(e)}")
            return None

    def update_status(self, scan_id: str, status: str) -> Optional[Scan]:
        """Update scan status."""
        from datetime import datetime
        update_data = {"status": status}
        if status == "running":
            update_data["started_at"] = datetime.utcnow()
        elif status in {"completed", "failed", "cancelled"}:
            update_data["completed_at"] = datetime.utcnow()
        
        return self.update(scan_id, update_data)

    def increment_retry(self, scan_id: str) -> Optional[Scan]:
        """Increment retry count."""
        scan = self.get_by_id(scan_id)
        if scan:
            return self.update(scan_id, {"retry_count": scan.retry_count + 1})
        return None

    def set_celery_task_id(self, scan_id: str, task_id: str) -> Optional[Scan]:
        """Set Celery task ID for a scan."""
        return self.update(scan_id, {"celery_task_id": task_id})

    def set_error(self, scan_id: str, error_message: str) -> Optional[Scan]:
        """Set error message for a failed scan."""
        return self.update(scan_id, {"error_message": error_message})
