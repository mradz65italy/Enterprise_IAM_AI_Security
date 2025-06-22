"""
Authentication and authorization endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64

from database.connection import get_db, get_redis
from database.models import User, AIModel, AuditLog, AccessAction, AuditLevel
from schemas.auth import (
    UserLogin, UserRegister, Token, AIModelAuth, AIModelToken,
    PasswordReset, PasswordResetConfirm, MFASetup, MFAVerify, ChangePassword
)
from services.auth_service import AuthService
from services.audit_service import AuditService
from utils.security import get_current_user, get_current_ai_model
from utils.error_handling import handle_database_errors, handle_redis_errors
from loguru import logger

router = APIRouter()
security = HTTPBearer()
auth_service = AuthService()
audit_service = AuditService()

@router.post("/login", response_model=Token)
@handle_database_errors(max_retries=3, retry_delay=1.0)
@handle_redis_errors(fallback_value=None)
async def login(
    request: Request,
    user_credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
    redis = Depends(get_redis)
):
    """
    Authenticate user and return access token
    """
    try:
        # Authenticate user
        user = await auth_service.authenticate_user(
            db, user_credentials.username, user_credentials.password
        )
        
        if not user:
            # Log failed authentication attempt
            await audit_service.log_security_event(
                db=db,
                event_type="login_failure",
                severity="medium",
                source_ip=request.client.host,
                description=f"Failed login attempt for username: {user_credentials.username}",
                details={"username": user_credentials.username}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password"
            )
        
        # Check if account is locked
        if user.account_locked_until and user.account_locked_until > datetime.utcnow():
            await audit_service.log_security_event(
                db=db,
                event_type="locked_account_access",
                severity="high",
                source_ip=request.client.host,
                description=f"Access attempt to locked account: {user.username}",
                details={"user_id": user.id, "locked_until": user.account_locked_until.isoformat()}
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked"
            )
        
        # Verify MFA if enabled
        if user.mfa_enabled:
            if not user_credentials.mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="MFA code required"
                )
            
            if not auth_service.verify_mfa(user.mfa_secret, user_credentials.mfa_code):
                await audit_service.log_security_event(
                    db=db,
                    event_type="mfa_failure",
                    severity="high",
                    source_ip=request.client.host,
                    description=f"MFA verification failed for user: {user.username}",
                    details={"user_id": user.id}
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )
        
        # Generate tokens
        access_token = auth_service.create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role.value}
        )
        refresh_token = auth_service.create_refresh_token(
            data={"sub": user.username, "user_id": user.id}
        )
        
        # Update user login info
        user.last_login = datetime.utcnow()
        user.failed_login_attempts = 0
        user.account_locked_until = None
        await db.commit()
        
        # Store refresh token in Redis
        await redis.setex(
            f"refresh_token:{user.id}",
            timedelta(days=7).total_seconds(),
            refresh_token
        )
        
        # Log successful authentication
        await audit_service.log_audit(
            db=db,
            user_id=user.id,
            action=AccessAction.LOGIN,
            resource_type="authentication",
            description=f"User {user.username} logged in successfully",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800  # 30 minutes
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable"
        )

@router.post("/register", response_model=dict)
async def register(
    request: Request,
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user
    """
    try:
        # Check if username already exists
        result = await db.execute(select(User).where(User.username == user_data.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Check if email already exists
        result = await db.execute(select(User).where(User.email == user_data.email))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create new user
        user = await auth_service.create_user(
            db=db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=user_data.role
        )
        
        # Log user registration
        await audit_service.log_audit(
            db=db,
            user_id=user.id,
            action=AccessAction.WRITE,
            resource_type="user",
            resource_id=str(user.id),
            description=f"New user registered: {user.username}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User registered successfully", "user_id": user.id}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration service unavailable"
        )

@router.post("/ai-model/authenticate", response_model=AIModelToken)
async def authenticate_ai_model(
    request: Request,
    model_credentials: AIModelAuth,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate AI model and return access token
    """
    try:
        # Authenticate AI model
        ai_model = await auth_service.authenticate_ai_model(
            db=db,
            model_id=model_credentials.model_id,
            api_key=model_credentials.api_key,
            network_location=model_credentials.network_location
        )
        
        if not ai_model:
            await audit_service.log_security_event(
                db=db,
                event_type="ai_model_auth_failure",
                severity="high",
                source_ip=request.client.host,
                description=f"Failed AI model authentication: {model_credentials.model_id}",
                details={"model_id": model_credentials.model_id, "network_location": model_credentials.network_location}
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid AI model credentials"
            )
        
        # Generate access token for AI model
        access_token = auth_service.create_ai_model_token(
            data={
                "sub": ai_model.model_id,
                "model_id": ai_model.id,
                "type": "ai_model",
                "capabilities": ai_model.capabilities
            }
        )
        
        # Update model's last authentication time
        ai_model.last_authenticated = datetime.utcnow()
        ai_model.last_seen = datetime.utcnow()
        await db.commit()
        
        # Log successful AI model authentication
        await audit_service.log_audit(
            db=db,
            ai_model_id=ai_model.id,
            action=AccessAction.LOGIN,
            resource_type="ai_model_authentication",
            description=f"AI model {ai_model.model_id} authenticated successfully",
            ip_address=request.client.host,
            network_location=model_credentials.network_location,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return AIModelToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=86400,  # 24 hours
            scopes=ai_model.allowed_operations or []
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI model authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI model authentication service unavailable"
        )

@router.post("/mfa/setup", response_model=MFASetup)
async def setup_mfa(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Setup Multi-Factor Authentication for user
    """
    try:
        # Generate MFA secret
        secret = pyotp.random_base32()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name="Enterprise AI IAM"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_base64 = base64.b64encode(buf.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = [pyotp.random_base32()[:8] for _ in range(10)]
        
        # Store MFA secret (temporarily - will be confirmed on verification)
        current_user.mfa_secret = secret
        await db.commit()
        
        # Log MFA setup
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.CONFIGURATION,
            resource_type="mfa",
            description="MFA setup initiated",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return MFASetup(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=backup_codes
        )
    
    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA setup service unavailable"
        )

@router.post("/mfa/verify")
async def verify_mfa(
    request: Request,
    mfa_data: MFAVerify,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify and enable MFA for user
    """
    try:
        if not current_user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not set up"
            )
        
        if not auth_service.verify_mfa(current_user.mfa_secret, mfa_data.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA code"
            )
        
        # Enable MFA
        current_user.mfa_enabled = True
        await db.commit()
        
        # Log MFA verification
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.CONFIGURATION,
            resource_type="mfa",
            description="MFA enabled successfully",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "MFA enabled successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA verification service unavailable"
        )

@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout user and invalidate tokens
    """
    try:
        # Remove refresh token from Redis
        await redis.delete(f"refresh_token:{current_user.id}")
        
        # Log logout
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.LOGOUT,
            resource_type="authentication",
            description=f"User {current_user.username} logged out",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "Logged out successfully"}
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service unavailable"
        )

@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user information
    """
    return {
        "id": current_user.id,
        "uuid": current_user.uuid,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "mfa_enabled": current_user.mfa_enabled,
        "last_login": current_user.last_login,
        "created_at": current_user.created_at
    }