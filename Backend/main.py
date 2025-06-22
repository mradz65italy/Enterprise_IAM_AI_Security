"""
Enterprise AI Identity and Access Management System
Main FastAPI application with improved startup handling
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
from loguru import logger
import sys
import time

# Configure logging
logger.remove()
logger.add(sys.stdout, format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}")

# Import configurations and dependencies
from config import settings
from database.connection import init_database, close_db_connections, check_db_health, check_redis_health

# Import routers
from routers import auth, ai_models, users, audit, permissions, dashboard

# Import middleware
from middleware.security import SecurityMiddleware
from middleware.audit import AuditMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management with proper startup sequence"""
    logger.info("Starting Enterprise AI IAM System...")
    
    startup_success = False
    max_startup_retries = 3  # Reduced from 5
    
    for attempt in range(max_startup_retries):
        try:
            logger.info(f"Startup attempt {attempt + 1}")
            
            # Reduced wait time
            logger.info("Waiting for dependencies...")
            await asyncio.sleep(2)  # Reduced from 5
            
            # Check database connection
            logger.info("Checking database connection...")
            db_healthy = await check_db_health()
            if not db_healthy:
                logger.warning("Database not healthy, continuing anyway for development")
                # Don't fail startup if database is not ready in development
            
            # Check Redis connection  
            logger.info("Checking Redis connection...")
            redis_healthy = await check_redis_health()
            if not redis_healthy:
                logger.warning("Redis not available, continuing without it")
            
            # Initialize database (skip if not healthy)
            if db_healthy:
                logger.info("Initializing database...")
                await init_database()
            else:
                logger.warning("Skipping database initialization")
            
            logger.info("Enterprise AI IAM System started successfully")
            startup_success = True
            break
            
        except Exception as e:
            logger.error(f"Startup attempt {attempt + 1} failed: {e}")
            if attempt < max_startup_retries - 1:
                await asyncio.sleep(3)  # Reduced from 10
            else:
                logger.warning("Failed to start after all retries, starting anyway")
                startup_success = True  # Allow startup even if checks fail
                break
    
    if not startup_success:
        raise Exception("Application failed to start")
    
    yield
    
    logger.info("Shutting down Enterprise AI IAM System...")
    await close_db_connections()

# Create FastAPI application
app = FastAPI(
    title="Enterprise AI Identity and Access Management",
    description="Comprehensive IAM system for managing AI model identities and access controls",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc", 
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add CORS middleware first
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add other middleware
app.add_middleware(SecurityMiddleware)
app.add_middleware(AuditMiddleware)

# Add request ID middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to all requests"""
    import uuid
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(f"Request {request_id} - {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.4f}s")
    
    response.headers["X-Request-ID"] = request_id
    return response

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        db_status = await check_db_health()
        redis_status = await check_redis_health()
        
        return {
            "status": "healthy" if db_status else "degraded",
            "version": "1.0.0",
            "timestamp": time.time(),
            "system": "Enterprise AI IAM",
            "database": "healthy" if db_status else "unhealthy", 
            "redis": "healthy" if redis_status else "unhealthy"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(ai_models.router, prefix="/api/v1/ai-models", tags=["AI Models"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit"])
app.include_router(permissions.router, prefix="/api/v1/permissions", tags=["Permissions"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disable reload for stability
        log_config=None  # Use loguru
    )
