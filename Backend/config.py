"""
Configuration settings for the Enterprise AI IAM System
"""

import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database settings
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql+asyncpg://iam_user:secure_password_123@postgres:5432/iam_ai_security"
    )
    
    # Redis settings
    REDIS_URL: str = os.getenv(
        "REDIS_URL", 
        "redis://:redis_password_123@redis:6379/0"
    )
    
    # Security settings
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", 
        "development-secret-key-change-in-production-environment"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Application settings
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"
    
    # CORS settings - allow frontend origins
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:8080",
        "http://localhost:3000", 
        "http://127.0.0.1:8080",
        "http://127.0.0.1:3000"
    ]
    
    # Performance settings for development
    BCRYPT_ROUNDS: int = 4  # Fast password hashing for development
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create global settings instance
settings = Settings()
