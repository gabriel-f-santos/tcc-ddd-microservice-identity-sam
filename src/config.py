from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Database
    database_url: str = Field(
        default="postgresql://inventory_user:inventory_password@localhost:5432/inventory_db",
        description="Database connection URL"
    )
    db_pool_size: int = Field(default=20, description="Database pool size")
    db_max_overflow: int = Field(default=30, description="Database pool max overflow")
    db_pool_timeout: int = Field(default=30, description="Database pool timeout")
    
    # JWT
    jwt_secret_key: str = Field(
        default="your-super-secret-jwt-key-change-this-in-production",
        description="JWT secret key"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_access_token_expire_minutes: int = Field(
        default=30, description="JWT token expiration in minutes"
    )
    
    # API
    api_v1_str: str = Field(default="/api/v1", description="API v1 prefix")
    project_name: str = Field(
        default="Inventory Management System", description="Project name"
    )
    debug: bool = Field(default=False, description="Debug mode")
    
    # Monitoring
    prometheus_enabled: bool = Field(default=False, description="Enable Prometheus metrics")
    prometheus_port: int = Field(default=8001, description="Prometheus metrics port")
    
    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format (json or text)")
    
    # CORS
    allowed_hosts: list[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0"],
        description="Allowed hosts for CORS"
    )
    
    # Pagination
    default_page_size: int = Field(default=20, description="Default pagination size")
    max_page_size: int = Field(default=100, description="Maximum pagination size")


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings."""
    return Settings()


# Dependency for FastAPI
def get_settings_dependency() -> Settings:
    """FastAPI dependency for settings."""
    return get_settings()