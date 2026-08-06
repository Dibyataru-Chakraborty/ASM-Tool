"""
Pydantic schemas for asset request/response validation.
"""

import json

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime


class AssetCreateRequest(BaseModel):
    """Create asset request."""
    name: str = Field(..., min_length=1, max_length=255)
    target: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None
    asset_type: str = Field(default="domain", pattern="^(domain|subdomain|ip|url|cidr|subnet|organization|ip_range|web_application|mobile_app|cloud_service)$")
    tags: list[str] = Field(default_factory=list)


class AssetUpdateRequest(BaseModel):
    """Update asset request."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    target: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|archived|monitoring)$")
    asset_type: Optional[str] = Field(None, pattern="^(domain|subdomain|ip|url|cidr|subnet|organization|ip_range|web_application|mobile_app|cloud_service)$")
    tags: Optional[list[str]] = None


class AssetResponse(BaseModel):
    """Asset in responses."""
    id: str
    name: str
    target: Optional[str] = None
    description: Optional[str] = None
    asset_type: str
    status: str
    is_active: bool = True
    risk_score: int
    tags: list[str] = Field(default_factory=list)
    scan_count: int = 0
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    @field_validator("tags", mode="before")
    @classmethod
    def parse_tags(cls, value):
        if value in (None, ""):
            return []
        if isinstance(value, list):
            return value
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            return [item.strip() for item in str(value).split(",") if item.strip()]

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_asset(cls, asset):
        return cls(
            id=asset.id,
            name=asset.name,
            target=asset.target,
            description=asset.description,
            asset_type=asset.asset_type,
            status=asset.status,
            is_active=asset.status == "active",
            risk_score=asset.risk_score,
            tags=asset.tags,
            scan_count=asset.scan_count or 0,
            last_scanned_at=asset.last_scanned_at,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
        )


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
    assets: list[AssetResponse] = Field(default_factory=list)


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
