"""
Application configuration — all keys required in .env, gracefully skipped if empty.
"""

from pydantic_settings import BaseSettings
from typing import Optional, List


class Settings(BaseSettings):

    # App
    app_name: str = "ASM Platform"
    app_version: str = "2.0.0"
    debug: bool = False
    environment: str = "development"
    log_level: str = "INFO"
    log_format: str = "text"
    secret_key: str = "change-me"

    # API
    api_prefix: str = "/api/v1"
    server_host: str = "0.0.0.0"
    server_port: int = 8000

    # CORS
    cors_origins: str = "http://localhost:3000"
    cors_credentials: bool = True
    cors_methods: list = ["*"]
    cors_headers: list = ["*"]
    api_title: str = "ASM Platform API"
    api_version: str = "2.0.0"

    # Database
    database_url: str = "postgresql://asm_user:asm_password@postgres:5432/asm_db"
    database_echo: bool = False
    database_pool_size: int = 20
    database_max_overflow: int = 40
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # JWT
    jwt_secret_key: str = "change-me-jwt"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # RBAC
    rbac_enabled: bool = True
    default_role: str = "analyst"

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"
    redis_cache_ttl: int = 3600
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    celery_task_timeout: int = 3600

    # Security / passwords
    password_min_length: int = 12
    password_require_special: bool = True
    password_require_numbers: bool = True
    password_require_uppercase: bool = True

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60

    # ─────────────────────────────────────────────────────────────
    #  AI PROVIDERS — all fields must exist; empty = skip provider
    # ─────────────────────────────────────────────────────────────
    gemini_api_key: Optional[str] = None       # PRIMARY AI
    claude_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    cohere_api_key: Optional[str] = None

    # ─────────────────────────────────────────────────────────────
    #  THREAT INTELLIGENCE — all fields must exist; empty = skip
    # ─────────────────────────────────────────────────────────────
    virustotal_api_key: Optional[str] = None   # PRIMARY TI
    shodan_api_key: Optional[str] = None        # PRIMARY TI
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    greynoise_api_key: Optional[str] = None

    # ─────────────────────────────────────────────────────────────
    #  PROJECTDISCOVERY tools
    # ─────────────────────────────────────────────────────────────
    pdcp_api_key: Optional[str] = None
    chaos_api_key: Optional[str] = None
    pd_tools_path: str = "/usr/local/bin"
    screenshot_timeout: int = 30
    screenshot_threads: int = 5
    screenshot_output_dir: str = "/app/screenshots"
    continuous_scan_interval_hours: int = 6
    max_concurrent_scans: int = 5
    scan_timeout_seconds: int = 3600

    # ─────────────────────────────────────────────────────────────
    #  NOTIFICATIONS
    # ─────────────────────────────────────────────────────────────
    github_token: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    slack_bot_token: Optional[str] = None
    azure_teams_webhook_url: Optional[str] = None
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: str = "asm-alerts@yourdomain.com"

    # misc external
    whois_cache_ttl: int = 604800
    dns_cache_ttl: int = 86400
    ssl_check_timeout: int = 10

    # ─────────────────────────────────────────────────────────────
    #  AI PENTESTER
    # ─────────────────────────────────────────────────────────────
    pentest_anthropic_api_key: Optional[str] = None
    pentest_output_dir: str = "/app/pentest-reports"
    pentest_workspace_dir: str = "/app/pentest-workspaces"
    pentest_max_concurrent_pipelines: int = 2
    pentest_small_model: str = "claude-haiku-4-5-20251001"
    pentest_medium_model: str = "claude-sonnet-4-6"
    pentest_large_model: str = "claude-opus-4-7"
    claude_code_max_output_tokens: int = 64000

    @property
    def cors_origins_list(self) -> List[str]:
        import json
        if self.cors_origins.startswith("["):
            try:
                return json.loads(self.cors_origins)
            except Exception:
                pass
        return [o.strip() for o in self.cors_origins.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


settings = Settings()
