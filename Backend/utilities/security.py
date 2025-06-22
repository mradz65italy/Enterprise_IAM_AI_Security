"""
Security utilities for authentication and authorization
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from jose import JWTError, jwt

from database.connection import get_db
from database.models import User, AIModel, UserRole, AIModelStatus
from services.auth_service import AuthService
from config import settings
from loguru import logger

security = HTTPBearer()
auth_service = AuthService()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth_service.verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception
        
        token_type = payload.get("type")
        if token_type != "access":
            raise credentials_exception
        
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        
        if username is None or user_id is None:
            raise credentials_exception
        
    except JWTError:
        raise credentials_exception
    
    # Get user from database
    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.username == username,
            User.is_active == True
        )
    )
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_ai_model(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> AIModel:
    """Get current authenticated AI model from JWT token"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate AI model credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = auth_service.verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception
        
        token_type = payload.get("type")
        if token_type != "ai_model":
            raise credentials_exception
        
        model_id: str = payload.get("sub")
        model_db_id: int = payload.get("model_id")
        
        if model_id is None or model_db_id is None:
            raise credentials_exception
        
    except JWTError:
        raise credentials_exception
    
    # Get AI model from database
    result = await db.execute(
        select(AIModel).where(
            AIModel.id == model_db_id,
            AIModel.model_id == model_id,
            AIModel.status == AIModelStatus.ACTIVE
        )
    )
    ai_model = result.scalar_one_or_none()
    
    if ai_model is None:
        raise credentials_exception
    
    return ai_model

async def get_current_user_or_ai_model(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> tuple[Optional[User], Optional[AIModel]]:
    """Get current authenticated user or AI model"""
    
    try:
        payload = auth_service.verify_token(credentials.credentials)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        token_type = payload.get("type")
        
        if token_type == "access":
            user = await get_current_user(credentials, db)
            return user, None
        elif token_type == "ai_model":
            ai_model = await get_current_ai_model(credentials, db)
            return None, ai_model
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

def require_role(required_role: UserRole):
    """Decorator to require specific user role"""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires {required_role.value} role"
            )
        return current_user
    return role_checker

def require_min_role(min_role: UserRole):
    """Decorator to require minimum user role"""
    role_hierarchy = {
        UserRole.VIEWER: 1,
        UserRole.AUDITOR: 2,
        UserRole.AI_MANAGER: 3,
        UserRole.ADMIN: 4,
        UserRole.SUPER_ADMIN: 5
    }
    
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if role_hierarchy.get(current_user.role, 0) < role_hierarchy.get(min_role, 0):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires minimum {min_role.value} role"
            )
        return current_user
    return role_checker

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin or super admin role"""
    if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

def require_super_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require super admin role"""
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin privileges required"
        )
    return current_user

async def check_permission(
    user: User,
    resource_type: str,
    action: str,
    db: AsyncSession
) -> bool:
    """Check if user has permission for specific action on resource type"""
    # This is a simplified permission check
    # In a full implementation, you would check against the permissions table
    
    role_permissions = {
        UserRole.SUPER_ADMIN: ["*"],  # All permissions
        UserRole.ADMIN: [
            "users:read", "users:write", "users:delete",
            "ai_models:read", "ai_models:write", "ai_models:delete",
            "audit:read", "permissions:read", "permissions:write"
        ],
        UserRole.AI_MANAGER: [
            "ai_models:read", "ai_models:write",
            "audit:read", "users:read"
        ],
        UserRole.AUDITOR: [
            "audit:read", "users:read", "ai_models:read"
        ],
        UserRole.VIEWER: [
            "users:read", "ai_models:read"
        ]
    }
    
    user_perms = role_permissions.get(user.role, [])
    
    # Super admin has all permissions
    if "*" in user_perms:
        return True
    
    # Check specific permission
    permission = f"{resource_type}:{action}"
    return permission in user_perms

async def validate_ai_model_access(
    ai_model: AIModel,
    required_operation: str,
    db: AsyncSession
) -> bool:
    """Validate if AI model has access to perform operation"""
    
    # Check if model is active
    if ai_model.status != AIModelStatus.ACTIVE:
        return False
    
    # Check allowed operations
    if ai_model.allowed_operations:
        return required_operation in ai_model.allowed_operations
    
    # If no specific operations defined, allow basic operations
    basic_operations = ["inference", "read", "heartbeat"]
    return required_operation in basic_operations

def generate_secure_token() -> str:
    """Generate a secure random token"""
    import secrets
    return secrets.token_urlsafe(32)

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def calculate_password_strength(password: str) -> dict:
    """Calculate password strength score and recommendations"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    if len(password) >= 12:
        score += 1
    
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Password should contain uppercase letters")
    
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Password should contain lowercase letters")
    
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Password should contain numbers")
    
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        score += 1
    else:
        feedback.append("Password should contain special characters")
    
    # Check for common patterns
    common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 1
        feedback.append("Password contains common patterns")
    
    strength_levels = {
        0: "Very Weak",
        1: "Weak", 
        2: "Fair",
        3: "Good",
        4: "Strong",
        5: "Very Strong",
        6: "Excellent"
    }
    
    return {
        "score": max(0, score),
        "strength": strength_levels.get(max(0, score), "Very Weak"),
        "feedback": feedback
    }