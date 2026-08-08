"""
Production ASM Scan Models
Full database schema for real scanning pipeline.
"""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Boolean, ForeignKey,
    Text, Float, DateTime, JSON, Index, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from app.models.base import Base, TimestampMixin, get_uuid
import enum


# ── Enums ─────────────────────────────────────────────────────────────────────

class AssetTypeEnum(str, enum.Enum):
    DOMAIN    = "domain"
    SUBDOMAIN = "subdomain"
    IP        = "ip"
    URL       = "url"
    CIDR      = "cidr"

class ScanStatusEnum(str, enum.Enum):
    QUEUED     = "queued"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    CANCELLED  = "cancelled"
    PAUSED     = "paused"

class ToolStatusEnum(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"

class SeverityEnum(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Asset ─────────────────────────────────────────────────────────────────────

class ASMAsset(Base, TimestampMixin):
    """User-registered asset to scan."""
    __tablename__ = "asm_assets"

    id          = Column(String(36), primary_key=True, default=get_uuid)
    user_id     = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name        = Column(String(255), nullable=False)               # display name
    target      = Column(String(512), nullable=False)               # actual target: domain/IP/CIDR/URL
    asset_type  = Column(String(20), nullable=False, default="domain")
    description = Column(Text, nullable=True)
    tags        = Column(JSON, default=list)
    is_active   = Column(Boolean, default=True)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    tenant_id   = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)

    schedules  = relationship("ScanSchedule", back_populates="asset", cascade="all, delete-orphan")
    scan_jobs  = relationship("ScanJob",      back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_asm_assets_user",   "user_id"),
        Index("idx_asm_assets_tenant", "tenant_id"),
        Index("idx_asm_assets_target", "target"),
    )


# ── Schedule ──────────────────────────────────────────────────────────────────

class ScanSchedule(Base, TimestampMixin):
    """Cron-based scan schedule per asset."""
    __tablename__ = "scan_schedules"

    id              = Column(String(36), primary_key=True, default=get_uuid)
    asset_id        = Column(String(36), ForeignKey("asm_assets.id", ondelete="CASCADE"), nullable=False)
    cron_expression = Column(String(100), nullable=False, default="0 2 * * *")  # daily 2am
    is_enabled      = Column(Boolean, default=True)
    is_paused       = Column(Boolean, default=False)
    next_run_at     = Column(DateTime(timezone=True), nullable=True)
    last_run_at     = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String(20), nullable=True)
    run_count       = Column(Integer, default=0)
    fail_count      = Column(Integer, default=0)
    max_retries     = Column(Integer, default=2)
    notify_on_completion = Column(Boolean, default=False)
    notify_email    = Column(String(255), nullable=True)

    asset     = relationship("ASMAsset",  back_populates="schedules")
    scan_jobs = relationship("ScanJob",   back_populates="schedule")

    __table_args__ = (
        Index("idx_schedule_asset",   "asset_id"),
        Index("idx_schedule_enabled", "is_enabled"),
        Index("idx_schedule_next",    "next_run_at"),
    )


# ── Scan Job ──────────────────────────────────────────────────────────────────

class ScanJob(Base, TimestampMixin):
    """One complete scan execution for one asset."""
    __tablename__ = "scan_jobs"

    id           = Column(String(36), primary_key=True, default=get_uuid)
    asset_id     = Column(String(36), ForeignKey("asm_assets.id", ondelete="CASCADE"), nullable=False)
    schedule_id  = Column(String(36), ForeignKey("scan_schedules.id", ondelete="SET NULL"), nullable=True)
    triggered_by = Column(String(20), default="manual")  # manual | schedule | api
    status       = Column(String(20), default="queued")
    progress     = Column(Integer, default=0)            # 0-100
    current_tool = Column(String(50), nullable=True)
    started_at   = Column(DateTime(timezone=True), nullable=True)
    finished_at  = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    celery_task_id = Column(String(255), nullable=True)

    asset      = relationship("ASMAsset",       back_populates="scan_jobs")
    schedule   = relationship("ScanSchedule",   back_populates="scan_jobs")
    tool_executions = relationship("ToolExecution", back_populates="scan_job",
                                   cascade="all, delete-orphan",
                                   order_by="ToolExecution.order_index")
    vulnerabilities = relationship("VulnFinding",   back_populates="scan_job",
                                   cascade="all, delete-orphan")
    scan_report = relationship("ScanReport",    back_populates="scan_job",
                               uselist=False,   cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_job_asset",  "asset_id"),
        Index("idx_scan_job_status", "status"),
    )


# ── Tool Execution ────────────────────────────────────────────────────────────

class ToolExecution(Base, TimestampMixin):
    """One tool run within a scan job."""
    __tablename__ = "tool_executions"

    id           = Column(String(36), primary_key=True, default=get_uuid)
    scan_job_id  = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    tool_name    = Column(String(50), nullable=False)    # subfinder, httpx, nmap, nuclei …
    order_index  = Column(Integer, nullable=False)
    status       = Column(String(20), default="pending")
    command      = Column(Text, nullable=True)           # exact CLI command used
    exit_code    = Column(Integer, nullable=True)
    started_at   = Column(DateTime(timezone=True), nullable=True)
    finished_at  = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    raw_output   = Column(Text, nullable=True)           # stdout
    error_output = Column(Text, nullable=True)           # stderr
    parsed_output = Column(JSON, nullable=True)          # structured results
    result_count = Column(Integer, default=0)            # how many items found
    error_message = Column(Text, nullable=True)
    retry_count  = Column(Integer, default=0)

    scan_job = relationship("ScanJob", back_populates="tool_executions")

    __table_args__ = (
        Index("idx_tool_exec_job",    "scan_job_id"),
        Index("idx_tool_exec_tool",   "tool_name"),
        Index("idx_tool_exec_status", "status"),
    )


# ── Vulnerability Finding ─────────────────────────────────────────────────────

class VulnFinding(Base, TimestampMixin):
    """Real vulnerability found by a tool."""
    __tablename__ = "vuln_findings"

    id              = Column(String(36), primary_key=True, default=get_uuid)
    scan_job_id     = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="SET NULL"), nullable=True)
    asset_id        = Column(String(36), ForeignKey("asm_assets.id", ondelete="CASCADE"), nullable=False)

    # Identity
    title           = Column(String(512), nullable=False)
    severity        = Column(String(20), nullable=False, default="info")
    cvss_score      = Column(Float, nullable=True)
    cvss_vector     = Column(String(255), nullable=True)
    cve_id          = Column(String(50), nullable=True)
    cwe_id          = Column(String(50), nullable=True)
    template_id     = Column(String(255), nullable=True)  # nuclei template

    # Location
    url             = Column(Text, nullable=True)
    host            = Column(String(255), nullable=True)
    port            = Column(Integer, nullable=True)
    parameter       = Column(String(255), nullable=True)
    path            = Column(Text, nullable=True)

    # Detail
    description     = Column(Text, nullable=True)
    impact          = Column(Text, nullable=True)
    recommendation  = Column(Text, nullable=True)
    references      = Column(JSON, default=list)
    tags            = Column(JSON, default=list)

    # Evidence
    http_request    = Column(Text, nullable=True)
    http_response   = Column(Text, nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    raw_evidence    = Column(Text, nullable=True)

    # Source tool
    source_tool     = Column(String(50), nullable=True)
    is_duplicate    = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)

    scan_job   = relationship("ScanJob",        back_populates="vulnerabilities")
    screenshots = relationship("VulnScreenshot", back_populates="vuln",
                               cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_vuln_scan",     "scan_job_id"),
        Index("idx_vuln_asset",    "asset_id"),
        Index("idx_vuln_severity", "severity"),
        Index("idx_vuln_findings_cve", "cve_id"),
    )


# ── Screenshot ────────────────────────────────────────────────────────────────

class VulnScreenshot(Base, TimestampMixin):
    """Screenshot associated with a vulnerability."""
    __tablename__ = "vuln_screenshots"

    id         = Column(String(36), primary_key=True, default=get_uuid)
    vuln_id    = Column(String(36), ForeignKey("vuln_findings.id", ondelete="CASCADE"), nullable=False)
    url        = Column(Text, nullable=True)
    file_path  = Column(String(512), nullable=True)
    file_size  = Column(Integer, nullable=True)
    width      = Column(Integer, nullable=True)
    height     = Column(Integer, nullable=True)
    taken_at   = Column(DateTime(timezone=True), nullable=True)

    vuln = relationship("VulnFinding", back_populates="screenshots")


# ── Scan Report ───────────────────────────────────────────────────────────────

class ScanReport(Base, TimestampMixin):
    """AI-generated report for a completed scan."""
    __tablename__ = "scan_reports"

    id              = Column(String(36), primary_key=True, default=get_uuid)
    scan_job_id     = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"),
                             nullable=False, unique=True)
    asset_id        = Column(String(36), ForeignKey("asm_assets.id", ondelete="CASCADE"), nullable=False)

    # Counts
    total_vulns     = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    high_count      = Column(Integer, default=0)
    medium_count    = Column(Integer, default=0)
    low_count       = Column(Integer, default=0)
    info_count      = Column(Integer, default=0)

    # AI content
    executive_summary  = Column(Text, nullable=True)
    technical_summary  = Column(Text, nullable=True)
    attack_surface     = Column(JSON, nullable=True)
    open_ports         = Column(JSON, default=list)
    technologies       = Column(JSON, default=list)
    subdomains_found   = Column(JSON, default=list)
    recommendations    = Column(Text, nullable=True)
    risk_score         = Column(Float, nullable=True)
    risk_rating        = Column(String(20), nullable=True)  # Critical/High/Medium/Low

    # Full report
    markdown_report = Column(Text, nullable=True)
    html_report     = Column(Text, nullable=True)
    json_report     = Column(JSON, nullable=True)

    # Export paths
    pdf_path        = Column(String(512), nullable=True)
    generated_at    = Column(DateTime(timezone=True), nullable=True)

    scan_job = relationship("ScanJob", back_populates="scan_report")

    __table_args__ = (
        Index("idx_report_scan",  "scan_job_id"),
        Index("idx_report_asset", "asset_id"),
    )


# ── Scan Log ──────────────────────────────────────────────────────────────────

class ScanLog(Base):
    """Append-only log for a scan job."""
    __tablename__ = "scan_logs"

    id          = Column(String(36), primary_key=True, default=get_uuid)
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    level       = Column(String(10), default="info")   # info|warn|error|debug
    message     = Column(Text, nullable=False)
    tool        = Column(String(50), nullable=True)
    logged_at   = Column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        Index("idx_log_scan", "scan_job_id"),
        Index("idx_log_time", "logged_at"),
    )
