"""
Application configuration management using Pydantic Settings.
All configuration is environment-driven. No hardcoded secrets.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # App
    app_name: str = "ASM Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"  # development, staging, production

    # API
    api_title: str = "Attack Surface Management Platform"
    api_version: str = "1.0.0"
    api_prefix: str = "/api/v1"

    # Server
    server_host: str = "0.0.0.0"
    server_port: int = 8000
    workers: int = 4

    # CORS
    cors_origins: list = ["http://localhost:3000", "http://localhost:8000"]
    cors_credentials: bool = True
    cors_methods: list = ["*"]
    cors_headers: list = ["*"]

    # Database
    database_url: str = "postgresql://asm_user:asm_password@postgres:5432/asm_db"
    database_echo: bool = False  # Log SQL queries
    database_pool_size: int = 20
    database_max_overflow: int = 40

    # JWT
    jwt_secret_key: str = "your-super-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # RBAC Roles
    rbac_enabled: bool = True
    default_role: str = "analyst"  # admin, analyst, viewer

    # Redis
    redis_url: str = "redis://redis:6379/0"
    redis_cache_ttl: int = 3600  # 1 hour

    # Celery
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    celery_task_timeout: int = 3600  # 1 hour

    # Persistent scan scheduler
    scheduler_poll_seconds: int = 15
    max_concurrent_scans: int = 5

    # Real scanner process limits. Set NUCLEI_SCAN_TIMEOUT_SECONDS=0 to let
    # Nuclei run without an overall process deadline.
    nuclei_scan_timeout_seconds: int = 7200
    
    nuclei_rate_limit: int = 100
    nuclei_concurrency: int = 35
    nuclei_bulk_size: int = 35
    nuclei_request_timeout: int = 10
    nuclei_retries: int = 1
    # Scanner executable locations and startup validation. The installer and
    # backend mount the same named volume at pd_tools_path, which keeps virtual
    # environment shebangs valid across both containers and across rebuilds.
    pd_tools_path: str = "/usr/local/pd_tools"
    nmap_path: str = "/usr/bin/nmap"
    chromium_path: str = "/usr/bin/chromium"
    recon_tool_probe_on_scan_start: bool = True
    recon_tool_probe_timeout_seconds: int = 15

    # Extended reconnaissance tools. Passive and low-impact discovery tools are
    # enabled by default. Duplicate, legacy, API-dependent, or active testing
    # tools remain opt-in so a normal recon scan does not overload the target.
    sublist3r_enabled: bool = True
    uncover_enabled: bool = True
    uncover_engine: str = "shodan-idb"
    uncover_limit: int = 50

    waybackurls_enabled: bool = True
    katana_enabled: bool = True
    katana_depth: int = 2
    paramspider_enabled: bool = True
    max_discovered_urls: int = 2000

    dirsearch_enabled: bool = True
    dirsearch_max_targets: int = 5
    dirsearch_timeout_seconds: int = 240
    dirsearch_max_rate: int = 20

    dirb_enabled: bool = False
    dirb_max_targets: int = 3
    dirbuster_enabled: bool = False
    dirbuster_max_targets: int = 2

    wappalyzer_enabled: bool = True
    wappalyzer_max_targets: int = 20

    wpscan_enabled: bool = True
    wpscan_api_token: Optional[str] = None
    wpscan_max_targets: int = 5
    wpscan_timeout_seconds: int = 600

    droopescan_enabled: bool = True
    droopescan_max_targets: int = 5
    droopescan_timeout_seconds: int = 300

    secretfinder_enabled: bool = True
    secretfinder_max_javascript_urls: int = 30

    # XSStrike sends active payloads. Keep disabled unless the user has explicit
    # authorization for active application testing.
    xsstrike_enabled: bool = False
    xsstrike_max_targets: int = 10
    xsstrike_timeout_seconds: int = 180
    
    # xss_vibes sends active reflected-XSS test payloads.
    xssvibes_enabled: bool = False
    xssvibes_max_targets: int = 20
    xssvibes_threads: int = 5
    xssvibes_timeout_seconds: int = 300

    # Nikto performs active web-server security checks.
    nikto_enabled: bool = False
    nikto_max_targets: int = 5
    nikto_timeout_seconds: int = 420

    # LazyRecon is a meta-wrapper around tools already present in this pipeline.
    # It can require root/masscan and is therefore installed but disabled here.
    lazyrecon_enabled: bool = False
    lazyrecon_timeout_seconds: int = 1800

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100  # requests per window
    rate_limit_window: int = 60  # seconds

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text
    structlog_enabled: bool = True

    # Security
    password_min_length: int = 12
    password_require_special: bool = True
    password_require_numbers: bool = True
    password_require_uppercase: bool = True

    # External Services (Phase 2+)
    whois_cache_ttl: int = 604800  # 7 days
    dns_cache_ttl: int = 86400  # 1 day
    ssl_check_timeout: int = 10  # seconds
    screenshot_timeout: int = 30  # seconds

    # AI Providers (Phase 7) - Vulnerability Analysis
    claude_api_key: Optional[str] = None  # Anthropic Claude
    openai_api_key: Optional[str] = None  # OpenAI GPT-4
    gemini_api_key: Optional[str] = None  # Google Gemini
    gemini_service_analysis_enabled: bool = True
    gemini_service_model: str = "gemini-3.6-flash"
    gemini_service_batch_size: int = 8
    gemini_service_max_unique_services: int = 50
    gemini_service_timeout_seconds: int = 120
    cohere_api_key: Optional[str] = None  # Cohere
    
    # Threat Intelligence APIs (Phase 4)
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    
    # GitHub (Phase 5)
    github_token: Optional[str] = None
    
    # Slack (Phase 6)
    slack_webhook_url: Optional[str] = None
    slack_bot_token: Optional[str] = None
    
    # Azure Teams (Phase 6)
    azure_webhook_url: Optional[str] = None

    # SMTP email notifications
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    smtp_require_auth: bool = True
    smtp_timeout_seconds: int = 20
    frontend_url: str = "http://localhost:3000"
    
    # AWS (Phase 5)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


# Singleton instance
settings = Settings()
