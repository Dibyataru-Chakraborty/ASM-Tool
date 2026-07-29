"""
Pydantic schemas for dashboard endpoints.
"""

from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


class RiskDistribution(BaseModel):
    """Risk distribution by severity."""
    critical: int
    high: int
    medium: int
    low: int


class RiskSummaryResponse(BaseModel):
    """Executive risk dashboard summary."""
    total_assets: int
    total_domains: int
    total_subdomains: int
    vulnerable_domains: int
    avg_risk_score: float
    risk_distribution: RiskDistribution
    timestamp: datetime


class AssetTimelineEvent(BaseModel):
    """Single timeline event."""
    scan_id: str
    type: str
    status: str
    timestamp: datetime
    discovered_count: int


class VulnerableDomain(BaseModel):
    """Vulnerable domain for dashboard."""
    domain_id: str
    domain: str
    risk_score: int
    last_scanned: Optional[datetime] = None


class ScanStatistics(BaseModel):
    """Scan execution statistics."""
    total_scans: int
    completed: int
    failed: int
    pending: int
    running: int
    success_rate: float


class HeatmapEntry(BaseModel):
    """Risk heatmap entry."""
    domain: str
    asset: str
    risk_level: str  # critical, high, medium, low
    risk_score: int
    is_vulnerable: bool
    subdomain_count: int


class DashboardFullResponse(BaseModel):
    """Complete dashboard data."""
    risk_summary: RiskSummaryResponse
    timeline: List[AssetTimelineEvent]
    vulnerable_domains: List[VulnerableDomain]
    scan_statistics: ScanStatistics
    heatmap: List[HeatmapEntry]
    
    # Front-end compatibility fields
    scans: Optional[dict] = None
    vulnerabilities: Optional[dict] = None
    running_scans: Optional[list] = None
    assets: Optional[int] = 0
