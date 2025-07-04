 """
Database connection and session management with retry logic
"""

import asyncio
import time
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import text
from config import settings
import redis.asyncio as aioredis
from loguru import logger

# Database URL with proper async driver
def get_async_database_url(url: str) -> str:
    """Convert database URL to async format safely"""
    if url.startswith("postgresql+asyncpg://"):
        return url
    elif url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    else:
        # Default to asyncpg if no driver specified
        return f"postgresql+asyncpg://{url}" if not url.startswith("postgresql") else url

DATABASE_URL = get_async_database_url(settings.DATABASE_URL)

# Create async engine with connection pooling
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=5,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={
        "server_settings": {
            "application_name": "enterprise_iam",
        },
        "command_timeout": 5,
    }
)

# Create async session maker
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Create Redis connection with retry
async def create_redis_client():
    """Create Redis client with connection retry"""
    max_retries = 5
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10,
                retry_on_timeout=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test connection
            await client.ping()
            logger.info("Redis connection established")
            return client
        except Exception as e:
            logger.warning(f"Redis connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Failed to connect to Redis after all retries")
                raise

# Initialize Redis client
redis_client = None

# Create base class for models
Base = declarative_base()

async def get_db() -> AsyncSession:
    """Dependency to get database session with retry logic"""
    max_retries = 3
    retry_delay = 1
    
    for attempt in range(max_retries):
        try:
            async with AsyncSessionLocal() as session:
                # Test connection
                await session.execute(text("SELECT 1"))
                yield session
                return
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Database connection failed after all retries")
                raise

async def get_redis():
    """Dependency to get Redis client"""
    global redis_client
    if redis_client is None:
        redis_client = await create_redis_client()
    return redis_client

async def close_db_connections():
    """Close all database connections"""
    global redis_client
    try:
        await engine.dispose()
        if redis_client:
            await redis_client.close()
    except Exception as e:
        logger.error(f"Error closing connections: {e}")

# Health check functions with timeout
async def check_db_health() -> bool:
    """Check database connectivity with timeout"""
    try:
        async with asyncio.wait_for(AsyncSessionLocal(), timeout=5) as session:
            await asyncio.wait_for(session.execute(text("SELECT 1")), timeout=5)
            return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False

async def check_redis_health() -> bool:
    """Check Redis connectivity with timeout"""
    try:
        client = await get_redis()
        await asyncio.wait_for(client.ping(), timeout=5)
        return True
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return False

# Database initialization with retry
async def init_database():
    """Initialize database with retry logic"""
    max_retries = 10
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Database initialization attempt {attempt + 1}")
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
            return True
        except Exception as e:
            logger.warning(f"Database init attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Database initialization failed after all retries")
                raise
    return False
