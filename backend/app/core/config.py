from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import List, Union
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        # This is key: don't try to parse JSON automatically
        env_parse_none_str=None
    )
    
    # Application
    APP_NAME: str = "Tanya-VAPT"
    APP_VERSION: str = "1.0.0"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    ENVIRONMENT: str = "production"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS - can be comma-separated string, wildcard "*", or list
    CORS_ORIGINS: Union[str, List[str]] = "http://localhost:3000"
    CORS_ALLOW_CREDENTIALS: bool = True

    @field_validator('CORS_ORIGINS', mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            # Allow wildcard for development
            if v.strip() == '*':
                return ['*']
            return [origin.strip() for origin in v.split(',')]
        return v

    # Database
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: str
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # Celery
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    # Anthropic
    ANTHROPIC_API_KEY: str
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    ANTHROPIC_MAX_TOKENS: int = 4096
    ANTHROPIC_BETA_VERSION: str = "computer-use-2025-01-24"

    # Browser
    BROWSER_TYPE: str = "chromium"
    BROWSER_HEADLESS: bool = True
    BROWSER_VIEWPORT_WIDTH: int = 1280
    BROWSER_VIEWPORT_HEIGHT: int = 800
    BROWSER_TIMEOUT: int = 30000

    # Display
    DISPLAY_NUMBER: int = 1
    DISPLAY_WIDTH_PX: int = 1280
    DISPLAY_HEIGHT_PX: int = 800

    # Scanning
    MAX_CRAWL_DEPTH: int = 5
    MAX_URLS_PER_DOMAIN: int = 10000
    CRAWL_DELAY_MS: int = 100

    # Discovery
    DISCOVER_HIDDEN_URLS: bool = True
    DISCOVER_API_ENDPOINTS: bool = True
    DISCOVER_JS_FILES: bool = True
    DISCOVER_STATIC_ASSETS: bool = True

    # VAPT
    ENABLE_SQL_INJECTION_TESTS: bool = True
    ENABLE_XSS_TESTS: bool = True
    ENABLE_CSRF_TESTS: bool = True
    ENABLE_AUTHENTICATION_BYPASS_TESTS: bool = True
    TEST_INTENSITY: str = "medium"
    TEST_PARALLEL_WORKERS: int = 5

    # AI Agents
    AGENT_PLANNING_ENABLED: bool = True
    AGENT_EXECUTION_ENABLED: bool = True
    AGENT_ANALYSIS_ENABLED: bool = True
    AGENT_SELF_HEALING_ENABLED: bool = True
    AGENT_MAX_RETRIES: int = 3

    # Context Management
    VECTOR_DB_ENABLED: bool = True
    VECTOR_DB_TYPE: str = "chromadb"
    CHUNK_SIZE: int = 1000
    CHUNK_OVERLAP: int = 200

    # Reporting
    REPORT_FORMAT: str = "pdf,html,json"
    REPORT_OUTPUT_DIR: str = "/reports"
    REPORT_INCLUDE_SCREENSHOTS: bool = True

    # Logging
    LOG_LEVEL: str = "info"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "/logs/tanya.log"
    AUDIT_LOG_ENABLED: bool = True

    # Storage
    STORAGE_PATH: str = "/data/storage"
    SCREENSHOT_STORAGE_PATH: str = "/data/screenshots"
    HAR_STORAGE_PATH: str = "/data/har_files"

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 100

    # Performance
    ENABLE_CACHING: bool = True
    CACHE_TTL_SECONDS: int = 3600
    MAX_PARALLEL_SCANS: int = 3


settings = Settings()
