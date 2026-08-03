"""
Dashboard API routes for executive risk dashboards.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.dashboard_service import DashboardService
from app.services.discovery_service import get_live_scan_state
from app.api.v1.dashboard.schemas import (
    RiskSummaryResponse,
    DashboardFullResponse,
)
from app.dependencies import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/risk-summary", response_model=RiskSummaryResponse)
async def get_risk_summary(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get executive risk dashboard summary."""
    try:
        service = DashboardService(db)
        summary = service.get_risk_summary(current_user.id)
        return summary
    except Exception as e:
        logger.error(f"Error getting risk summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get risk summary")


@router.get("/timeline")
async def get_activity_timeline(
    days: int = Query(30, ge=1, le=365),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get asset activity timeline."""
    try:
        service = DashboardService(db)
        timeline = service.get_asset_timeline(current_user.id, days)
        return {"timeline": timeline}
    except Exception as e:
        logger.error(f"Error getting timeline: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get timeline")


@router.get("/vulnerable-domains")
async def get_vulnerable_domains(
    limit: int = Query(10, ge=1, le=100),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get top vulnerable domains."""
    try:
        service = DashboardService(db)
        domains = service.get_top_vulnerable_domains(current_user.id, limit)
        return {"vulnerable_domains": domains}
    except Exception as e:
        logger.error(f"Error getting vulnerable domains: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get vulnerable domains")


@router.get("/scan-statistics")
async def get_scan_statistics(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get scan execution statistics."""
    try:
        service = DashboardService(db)
        stats = service.get_scan_statistics(current_user.id)
        return stats
    except Exception as e:
        logger.error(f"Error getting scan statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get scan statistics")


@router.get("/risk-heatmap")
async def get_risk_heatmap(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get domain risk heatmap."""
    try:
        service = DashboardService(db)
        heatmap = service.get_domain_risk_heatmap(current_user.id)
        return {"heatmap": heatmap}
    except Exception as e:
        logger.error(f"Error getting heatmap: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get heatmap")


@router.get("/full", response_model=DashboardFullResponse)
async def get_full_dashboard(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get complete dashboard data (all widgets)."""
    try:
        from app.models import Scan, Asset
        service = DashboardService(db)
        
        risk_summary = service.get_risk_summary(current_user.id)
        timeline = service.get_asset_timeline(current_user.id, 30)
        vulnerable_domains = service.get_top_vulnerable_domains(current_user.id, 10)
        scan_stats = service.get_scan_statistics(current_user.id)
        heatmap = service.get_domain_risk_heatmap(current_user.id)
        
        # Populate front-end compatibility data
        scans = {
            "total": scan_stats.get("total_scans", 0),
            "completed": scan_stats.get("completed", 0),
            "failed": scan_stats.get("failed", 0),
            "running": scan_stats.get("running", 0),
            "queued": scan_stats.get("pending", 0),
        }
        
        vulnerabilities = {
            "total": sum(risk_summary["risk_distribution"].values()),
            "critical": risk_summary["risk_distribution"].get("critical", 0),
            "high": risk_summary["risk_distribution"].get("high", 0),
            "medium": risk_summary["risk_distribution"].get("medium", 0),
            "low": risk_summary["risk_distribution"].get("low", 0),
        }
        
        running_scans = db.query(Scan).join(Asset).filter(
            Asset.user_id == current_user.id,
            Scan.status.in_(["running", "pending"])
        ).all()
        
        running_list = []
        for s in running_scans:
            live_state = get_live_scan_state(s.id)
            running_list.append({
                "id": s.id,
                "asset_id": s.asset_id,
                "asset_target": s.asset.name,
                "status": s.status,
                "current_tool": None,
                "progress": live_state.get(
                    "progress",
                    0,
                ),
            })
            
        assets_count = risk_summary.get("total_assets", 0)
        
        return {
            "risk_summary": risk_summary,
            "timeline": timeline,
            "vulnerable_domains": vulnerable_domains,
            "scan_statistics": scan_stats,
            "heatmap": heatmap,
            "scans": scans,
            "vulnerabilities": vulnerabilities,
            "running_scans": running_list,
            "assets": assets_count,
        }
    except Exception as e:
        logger.error(f"Error getting full dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard")
