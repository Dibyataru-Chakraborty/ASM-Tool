"""
Pydantic schemas for asset request/response validation.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime


class AssetCreateRequest(BaseModel):
    """Create asset request."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    asset_type: str = Field(default="domain", pattern="^(domain|ip|subnet|organization|ip_range|web_application|mobile_app|cloud_service)$")

    @field_validator("name")
    def validate_name(cls, v):
        blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
        for b in blocked:
            if b in v:
                raise ValueError(f"Character '{b}' is not allowed in name")
        return v

    @field_validator("description")
    def sanitize_description(cls, v):
        if v:
            return v.replace("<", "").replace(">", "")
        return v


class AssetUpdateRequest(BaseModel):
    """Update asset request."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|archived|monitoring)$")

    @field_validator("name")
    def validate_name(cls, v):
        if v:
            blocked = [";", "&", "|", "$", "<", ">", '"', "'", "`"]
            for b in blocked:
                if b in v:
                    raise ValueError(f"Character '{b}' is not allowed in name")
        return v

    @field_validator("description")
    def sanitize_description(cls, v):
        if v:
            return v.replace("<", "").replace(">", "")
        return v


class AssetResponse(BaseModel):
    """Asset in responses."""
    id: str
    name: str
    description: Optional[str] = None
    asset_type: str
    status: str
    risk_score: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetDetailResponse(AssetResponse):
    """Detailed asset response with statistics."""
    total_domains: int = 0
    total_subdomains: int = 0
    vulnerable_domains: int = 0


class AssetListResponse(BaseModel):
    """Asset list with pagination."""
    total: int
    skip: int
    limit: int
    items: list[AssetResponse]


class AssetStatsResponse(BaseModel):
    """Asset statistics."""
    asset_id: str
    name: str
    total_domains: int
    vulnerable_domains: int
    total_subdomains: int
    risk_score: int
    status: str
    last_scanned: Optional[datetime] = None


class DomainCreateRequest(BaseModel):
    """Create domain request."""
    domain: str = Field(..., min_length=1)
    asset_id: str


class SubdomainResponse(BaseModel):
    """Subdomain in responses."""
    id: str
    subdomain: str
    is_responsive: bool
    response_status_code: Optional[int] = None
    has_ssl: bool
    ip_addresses: list[str] = []
    created_at: datetime

    class Config:
        from_attributes = True


class DomainResponse(BaseModel):
    """Domain in responses."""
    id: str
    domain: str
    tld: Optional[str] = None
    registrar: Optional[str] = None
    expiration_date: Optional[datetime] = None
    is_vulnerable: bool
    last_scanned: Optional[datetime] = None
    subdomain_count: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class DomainDetailResponse(DomainResponse):
    """Detailed domain response."""
    subdomains: list[SubdomainResponse] = []
    dns_records: list[dict] = []
    ssl_certificates: list[dict] = []
