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
    database_url: str
    database_echo: bool = False  # Log SQL queries
    database_pool_size: int = 20
    database_max_overflow: int = 40

    # JWT
    jwt_secret_key: str
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
    
    # AWS (Phase 5)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"

    # Super Admin Bootstrap
    bootstrap_super_admin_email: Optional[str] = None
    bootstrap_super_admin_password: Optional[str] = None
    bootstrap_super_admin_name: Optional[str] = None

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


# Singleton instance
settings = Settings()
