"""
Dashboard API routes for executive risk dashboards.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.utils.database import get_db
from app.services.dashboard_service import DashboardService
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
        service = DashboardService(db)
        
        risk_summary = service.get_risk_summary(current_user.id)
        timeline = service.get_asset_timeline(current_user.id, 30)
        vulnerable_domains = service.get_top_vulnerable_domains(current_user.id, 10)
        scan_stats = service.get_scan_statistics(current_user.id)
        heatmap = service.get_domain_risk_heatmap(current_user.id)
        
        return {
            "risk_summary": risk_summary,
            "timeline": timeline,
            "vulnerable_domains": vulnerable_domains,
            "scan_statistics": scan_stats,
            "heatmap": heatmap,
        }
    except Exception as e:
        logger.error(f"Error getting full dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard")
