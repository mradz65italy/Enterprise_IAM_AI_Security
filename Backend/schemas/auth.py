"""
Authentication and authorization schemas
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from database.models import UserRole

class UserLogin(BaseModel):
    """User login request"""
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)
    mfa_code: Optional[str] = Field(None, pattern="^[0-9]{6}$")

class UserRegister(BaseModel):
    """User registration request"""
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2, max_length=255)
    role: UserRole = UserRole.VIEWER

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class Token(BaseModel):
    """JWT token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    """Token payload data"""
    username: Optional[str] = None
    user_id: Optional[int] = None
    role: Optional[str] = None
    scopes: List[str] = []

class AIModelAuth(BaseModel):
    """AI Model authentication request"""
    model_id: str = Field(..., min_length=1, max_length=100)
    api_key: str = Field(..., min_length=32)
    network_location: str = Field(..., max_length=255)
    certificate_fingerprint: Optional[str] = None

class AIModelToken(BaseModel):
    """AI Model access token"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scopes: List[str] = []

class PasswordReset(BaseModel):
    """Password reset request"""
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    """Password reset confirmation"""
    token: str
    new_password: str = Field(..., min_length=8)

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class MFASetup(BaseModel):
    """MFA setup response"""
    secret: str
    qr_code: str
    backup_codes: List[str]

class MFAVerify(BaseModel):
    """MFA verification request"""
    code: str = Field(..., pattern="^[0-9]{6}$")

class ChangePassword(BaseModel):
    """Change password request"""
    current_password: str
    new_password: str = Field(..., min_length=8)

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v