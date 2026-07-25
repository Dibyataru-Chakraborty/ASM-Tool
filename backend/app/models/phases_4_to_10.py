"""
Phases 4-8 Models: Threat Intelligence, Secret Detection, Monitoring, Enterprise.
"""

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, Index, Text, DateTime, Float
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid


class ThreatIntelligence(Base, TimestampMixin):
    """Phase 4: Threat intelligence from external sources."""
    __tablename__ = "threat_intelligence"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    indicator_type = Column(String(50), nullable=False)  # IP, Domain, Email, Hash
    indicator_value = Column(String(255), nullable=False)
    source = Column(String(100), nullable=False)  # VirusTotal, AbuseIPDB, Shodan, etc.
    reputation_score = Column(Float, nullable=True)
    is_malicious = Column(Boolean, default=False)
    details = Column(Text, nullable=True)  # JSON
    last_checked = Column(DateTime(timezone=True), nullable=True)
    
    __table_args__ = (
        Index("idx_ti_indicator", "indicator_type", "indicator_value"),
        Index("idx_ti_malicious", "is_malicious"),
    )


class Secret(Base, TimestampMixin):
    """Phase 5: Detected secrets (API keys, tokens, credentials)."""
    __tablename__ = "secrets"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=True)
    secret_type = Column(String(100), nullable=False)  # AWS_KEY, API_KEY, GITHUB_TOKEN, etc.
    secret_location = Column(String(255), nullable=False)  # File, git history, env, etc.
    confidence = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    remediation_status = Column(String(50), default="pending")  # pending, fixed, false_positive
    
    __table_args__ = (
        Index("idx_secrets_type", "secret_type"),
        Index("idx_secrets_active", "is_active"),
    )


class Alert(Base, TimestampMixin):
    """Phase 6: Monitoring alerts."""
    __tablename__ = "alerts"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    alert_type = Column(String(100), nullable=False)  # NewVuln, SecretFound, DomainExpiring, etc.
    severity = Column(String(20), nullable=False)  # Critical, High, Medium, Low
    message = Column(Text, nullable=False)
    is_resolved = Column(Boolean, default=False)
    notification_channels = Column(String(255), nullable=True)  # email,slack,teams,webhook
    
    __table_args__ = (
        Index("idx_alerts_asset", "asset_id"),
        Index("idx_alerts_resolved", "is_resolved"),
    )


class AIInsight(Base, TimestampMixin):
    """Phase 7: AI-generated insights and recommendations."""
    __tablename__ = "ai_insights"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    insight_type = Column(String(100), nullable=False)  # risk_assessment, remediation, prioritization
    content = Column(Text, nullable=False)  # AI-generated content
    confidence_score = Column(Float, default=0.0)
    
    __table_args__ = (
        Index("idx_ai_asset", "asset_id"),
    )


class Tenant(Base, TimestampMixin):
    """Phase 8: Multi-tenancy support."""
    __tablename__ = "tenants"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    subscription_tier = Column(String(50), default="free")  # free, pro, enterprise
    api_quota_daily = Column(Integer, default=10000)
    
    __table_args__ = (
        Index("idx_tenants_slug", "slug"),
    )


class AuditLog(Base, TimestampMixin):
    """Phase 8: Audit logging for enterprise compliance."""
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    action = Column(String(100), nullable=False)  # create_asset, run_scan, etc.
    resource_type = Column(String(50), nullable=False)  # asset, scan, user, etc.
    resource_id = Column(String(36), nullable=True)
    details = Column(Text, nullable=True)  # JSON
    ip_address = Column(String(50), nullable=True)
    
    __table_args__ = (
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_action", "action"),
    )


class Report(Base, TimestampMixin):
    """Phase 9: Report generation and storage."""
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String(50), nullable=False)  # executive, technical, compliance
    format = Column(String(20), nullable=False)  # pdf, excel, html
    title = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=True)  # S3 or local path
    status = Column(String(50), default="generated")  # generating, generated, failed
    
    __table_args__ = (
        Index("idx_reports_asset", "asset_id"),
    )


class BackupRestore(Base, TimestampMixin):
    """Phase 10: Backup and restore operations."""
    __tablename__ = "backups"
    
    id = Column(String(36), primary_key=True, default=get_uuid)
    backup_type = Column(String(50), nullable=False)  # full, incremental
    status = Column(String(50), default="pending")  # pending, completed, failed
    backup_path = Column(String(512), nullable=False)
    size_bytes = Column(Integer, nullable=True)
    restore_point_date = Column(DateTime(timezone=True), nullable=True)
