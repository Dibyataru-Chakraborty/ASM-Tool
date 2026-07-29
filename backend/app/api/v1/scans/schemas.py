"""
Pydantic schemas for scan request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ScanInitiateRequest(BaseModel):
    """Initiate scan request."""
    asset_id: str
    domain_id: Optional[str] = None
    target_domain: Optional[str] = None
    scan_type: str = Field(default="discovery", pattern="^(discovery|ssl|screenshot|dns|port_scan|tech_detect|full|quick|vuln_scan|ssl_check)$")


class TriggerScanRequest(BaseModel):
    """Trigger scan from asset page — only asset_id required."""
    asset_id: str
    scan_type: str = "discovery"


class ScanResponse(BaseModel):
    """Scan in responses."""
    id: str
    asset_id: str
    scan_type: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    discovered_count: int
    vulnerable_count: int
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    # Frontend compatibility: expose id as scan_job_id
    @property
    def scan_job_id(self):
        return self.id

    class Config:
        from_attributes = True


class DomainDiscoveryRequest(BaseModel):
    """Domain discovery request."""
    asset_id: str
    domain: str = Field(..., min_length=1)


class DomainDiscoveryResponse(BaseModel):
    """Domain discovery response."""
    domain_id: str
    domain: str
    subdomains_found: int
    dns_records_found: int
    status: str
    created_at: datetime


class ScanListResponse(BaseModel):
    """Scan list with pagination."""
    total: int
    skip: int
    limit: int
    items: list[ScanResponse]
