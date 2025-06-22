"""
Enhanced error handling utilities for the Enterprise AI IAM System
"""

import asyncio
from functools import wraps
from typing import Callable, Any
from fastapi import HTTPException, status
from sqlalchemy.exc import (
    SQLAlchemyError, 
    DisconnectionError, 
    TimeoutError as SQLTimeoutError,
    OperationalError
)
from loguru import logger
import redis.exceptions


def handle_database_errors(max_retries: int = 3, retry_delay: float = 1.0):
    """
    Decorator to handle database connection errors with retry logic
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                    
                except (DisconnectionError, OperationalError, SQLTimeoutError) as e:
                    last_exception = e
                    logger.warning(
                        f"Database error on attempt {attempt + 1}/{max_retries} "
                        f"in {func.__name__}: {str(e)}"
                    )
                    
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                        continue
                    
                    # Final attempt failed
                    logger.error(f"Database operation failed after {max_retries} attempts: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Database service temporarily unavailable"
                    )
                    
                except SQLAlchemyError as e:
                    logger.error(f"Database error in {func.__name__}: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Database operation failed"
                    )
                    
                except Exception as e:
                    logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Internal server error"
                    )
            
            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
                
        return wrapper
    return decorator


def handle_redis_errors(fallback_value: Any = None):
    """
    Decorator to handle Redis connection errors gracefully
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            try:
                return await func(*args, **kwargs)
                
            except (
                redis.exceptions.ConnectionError,
                redis.exceptions.TimeoutError,
                redis.exceptions.RedisError
            ) as e:
                logger.warning(f"Redis error in {func.__name__}: {str(e)}")
                
                # Return fallback value or raise HTTP exception based on criticality
                if fallback_value is not None:
                    return fallback_value
                else:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Cache service temporarily unavailable"
                    )
                    
            except Exception as e:
                logger.error(f"Unexpected error in Redis operation {func.__name__}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error"
                )
                
        return wrapper
    return decorator


async def safe_database_operation(operation: Callable, *args, **kwargs) -> Any:
    """
    Execute database operation with timeout and error handling
    """
    try:
        # Set timeout for database operations
        return await asyncio.wait_for(
            operation(*args, **kwargs),
            timeout=30.0  # 30 second timeout
        )
    except asyncio.TimeoutError:
        logger.error(f"Database operation timed out: {operation.__name__}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Database operation timed out"
        )
    except Exception as e:
        logger.error(f"Database operation failed: {operation.__name__} - {str(e)}")
        raise


class DatabaseHealthChecker:
    """
    Utility class for checking database health with circuit breaker pattern
    """
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = 0
        self.circuit_open = False
    
    def is_circuit_open(self) -> bool:
        """Check if circuit breaker is open"""
        if self.circuit_open:
            # Check if enough time has passed to attempt recovery
            current_time = asyncio.get_event_loop().time()
            if current_time - self.last_failure_time > self.recovery_timeout:
                self.circuit_open = False
                self.failure_count = 0
                logger.info("Circuit breaker reset, attempting recovery")
        
        return self.circuit_open
    
    def record_success(self):
        """Record successful operation"""
        self.failure_count = 0
        self.circuit_open = False
    
    def record_failure(self):
        """Record failed operation"""
        self.failure_count += 1
        self.last_failure_time = asyncio.get_event_loop().time()
        
        if self.failure_count >= self.failure_threshold:
            self.circuit_open = True
            logger.warning(
                f"Circuit breaker opened after {self.failure_count} failures"
            )


# Global circuit breaker instance
db_health_checker = DatabaseHealthChecker()