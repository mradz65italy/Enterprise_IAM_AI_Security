"""
Authentication service with enterprise security features
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext
from jose import JWTError, jwt
import pyotp
import secrets
import hashlib

from database.models import User, AIModel, UserRole, AIModelStatus
from config import settings
from loguru import logger

class AuthService:
    """Authentication and authorization service"""
    
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against its hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Hash a password"""
        return self.pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({"exp": expire, "type": "refresh"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_ai_model_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT token for AI models"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(hours=settings.AI_MODEL_TOKEN_EXPIRE_HOURS)
        
        to_encode.update({"exp": expire, "type": "ai_model"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.error(f"Token verification failed: {e}")
            return None
    
    async def authenticate_user(self, db: AsyncSession, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        try:
            result = await db.execute(
                select(User).where(
                    (User.username == username) | (User.email == username),
                    User.is_active == True
                )
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return None
            
            if not self.verify_password(password, user.hashed_password):
                # Increment failed login attempts
                user.failed_login_attempts += 1
                
                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                
                await db.commit()
                return None
            
            return user
        
        except Exception as e:
            logger.error(f"User authentication error: {e}")
            return None
    
    async def authenticate_ai_model(
        self, 
        db: AsyncSession, 
        model_id: str, 
        api_key: str, 
        network_location: str
    ) -> Optional[AIModel]:
        """Authenticate AI model"""
        try:
            # Hash the provided API key
            api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            
            result = await db.execute(
                select(AIModel).where(
                    AIModel.model_id == model_id,
                    AIModel.status == AIModelStatus.ACTIVE,
                    AIModel.api_key_hash == api_key_hash
                )
            )
            ai_model = result.scalar_one_or_none()
            
            if not ai_model:
                return None
            
            # Verify network location (simple check - can be enhanced)
            if ai_model.network_location != network_location:
                logger.warning(f"Network location mismatch for AI model {model_id}")
                # In a real system, you might want to be more flexible with network location
                # For now, we'll allow it but log the discrepancy
            
            return ai_model
        
        except Exception as e:
            logger.error(f"AI model authentication error: {e}")
            return None
    
    async def create_user(
        self,
        db: AsyncSession,
        username: str,
        email: str,
        password: str,
        full_name: str,
        role: UserRole = UserRole.VIEWER
    ) -> User:
        """Create a new user"""
        try:
            hashed_password = self.get_password_hash(password)
            
            user = User(
                username=username,
                email=email,
                hashed_password=hashed_password,
                full_name=full_name,
                role=role,
                is_active=True,
                is_verified=False
            )
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            return user
        
        except Exception as e:
            logger.error(f"User creation error: {e}")
            await db.rollback()
            raise
    
    def generate_api_key(self) -> str:
        """Generate a secure API key"""
        return secrets.token_urlsafe(32)
    
    def hash_api_key(self, api_key: str) -> str:
        """Hash an API key"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def verify_mfa(self, secret: str, code: str) -> bool:
        """Verify MFA code"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=1)  # Allow 1 time step tolerance
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            return False
    
    def generate_mfa_secret(self) -> str:
        """Generate MFA secret"""
        return pyotp.random_base32()
    
    async def change_password(
        self, 
        db: AsyncSession, 
        user: User, 
        current_password: str, 
        new_password: str
    ) -> bool:
        """Change user password"""
        try:
            # Verify current password
            if not self.verify_password(current_password, user.hashed_password):
                return False
            
            # Hash new password
            new_hashed_password = self.get_password_hash(new_password)
            
            # Update password
            user.hashed_password = new_hashed_password
            user.updated_at = datetime.utcnow()
            
            await db.commit()
            return True
        
        except Exception as e:
            logger.error(f"Password change error: {e}")
            await db.rollback()
            return False
    
    def is_password_strong(self, password: str) -> bool:
        """Check if password meets strength requirements"""
        if len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    async def validate_network_location(self, db: AsyncSession, ip_address: str) -> bool:
        """Validate if network location is allowed"""
        # This is a placeholder - implement your network validation logic
        # You might check against approved IP ranges, corporate networks, etc.
        return True
    
    def calculate_risk_score(self, user: User, ip_address: str, user_agent: str) -> int:
        """Calculate risk score for authentication attempt"""
        risk_score = 0
        
        # Check failed login attempts
        if user.failed_login_attempts > 0:
            risk_score += user.failed_login_attempts * 10
        
        # Check if account was recently created
        if user.created_at > datetime.utcnow() - timedelta(days=1):
            risk_score += 20
        
        # Check if login from new location (simplified)
        # In real implementation, you'd track user's usual locations
        
        # Check time of access (outside business hours = higher risk)
        current_hour = datetime.utcnow().hour
        if current_hour < 6 or current_hour > 22:
            risk_score += 15
        
        return min(risk_score, 100)  # Cap at 100