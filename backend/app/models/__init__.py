"""
SQLAlchemy ORM models - All Phases.
"""

from app.models.base import Base, TimestampMixin, get_uuid
from app.models.user import User
from app.models.organization import Organization, OrganizationMembership, OrganizationAuditLog
from app.models.asset import Asset
from app.models.domain import Domain
from app.models.subdomain import Subdomain
from app.models.dns_record import DNSRecord
from app.models.ssl_certificate import SSLCertificate
from app.models.screenshot import Screenshot
from app.models.scan import Scan
from app.models.scan_schedule import ScanSchedule
from app.models.ai_service_assessment import AIServiceAssessment
from app.models.attack_surface import (
    DiscoverySeed, DiscoveredAsset, AssetRelationship, AssetObservation, AssetChange, Exposure
)

# Phase 2-3: Port Scanning, Service Detection, Vulnerability
from app.models.phase2 import Port, Service, Banner, Technology, OSDetection, Vulnerability

# Phase 4-10: Advanced features
from app.models.phases_4_to_10 import (
    ThreatIntelligence, Secret, Alert, AIInsight, 
    Tenant, AuditLog, Report, BackupRestore
)

__all__ = [
    "Base",
    "TimestampMixin",
    "get_uuid",
    # Phase 1
    "User",
    "Organization",
    "OrganizationMembership",
    "OrganizationAuditLog",
    "Asset",
    "Domain",
    "Subdomain",
    "DNSRecord",
    "SSLCertificate",
    "Screenshot",
    "Scan",
    "ScanSchedule",
    "AIServiceAssessment",
    "DiscoverySeed",
    "DiscoveredAsset",
    "AssetRelationship",
    "AssetObservation",
    "AssetChange",
    "Exposure",
    # Phase 2-3
    "Port",
    "Service",
    "Banner",
    "Technology",
    "OSDetection",
    "Vulnerability",
    # Phase 4-10
    "ThreatIntelligence",
    "Secret",
    "Alert",
    "AIInsight",
    "Tenant",
    "AuditLog",
    "Report",
    "BackupRestore",
]
