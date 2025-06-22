"""
Pydantic schemas for AI Models
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from database.models import AIModelType, AIModelStatus

class AIModelCreate(BaseModel):
    """Schema for creating AI model"""
    model_id: str = Field(..., min_length=1, max_length=100)
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    model_type: AIModelType
    version: str = Field(..., min_length=1, max_length=50)
    network_location: str = Field(..., max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    endpoint_path: Optional[str] = Field(None, max_length=255)
    allowed_operations: Optional[List[str]] = None
    resource_limits: Optional[Dict[str, Any]] = None
    capabilities: Optional[Dict[str, Any]] = None
    hardware_requirements: Optional[Dict[str, Any]] = None
    compliance_tags: Optional[List[str]] = None

    @validator('model_id')
    def validate_model_id(cls, v):
        """Validate model ID format"""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Model ID must contain only alphanumeric characters, hyphens, and underscores')
        return v

class AIModelUpdate(BaseModel):
    """Schema for updating AI model"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    version: Optional[str] = Field(None, min_length=1, max_length=50)
    network_location: Optional[str] = Field(None, max_length=255)
    port: Optional[int] = Field(None, ge=1, le=65535)
    endpoint_path: Optional[str] = Field(None, max_length=255)
    allowed_operations: Optional[List[str]] = None
    resource_limits: Optional[Dict[str, Any]] = None
    capabilities: Optional[Dict[str, Any]] = None
    hardware_requirements: Optional[Dict[str, Any]] = None
    compliance_tags: Optional[List[str]] = None

class AIModelResponse(BaseModel):
    """Basic AI model response schema"""
    id: int
    uuid: str
    model_id: str
    name: str
    description: Optional[str]
    model_type: AIModelType
    version: str
    status: AIModelStatus
    network_location: str
    port: Optional[int]
    last_seen: Optional[datetime]
    last_authenticated: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AIModelDetail(AIModelResponse):
    """Detailed AI model response schema"""
    endpoint_path: Optional[str]
    allowed_operations: Optional[List[str]]
    resource_limits: Optional[Dict[str, Any]]
    capabilities: Optional[Dict[str, Any]]
    hardware_requirements: Optional[Dict[str, Any]]
    compliance_tags: Optional[List[str]]
    registration_approved_at: Optional[datetime]
    owner_id: int

class AIModelList(BaseModel):
    """AI model list response"""
    models: List[AIModelResponse]
    total: int
    skip: int
    limit: int

class AIModelToken(BaseModel):
    """AI model access token"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scopes: List[str] = []

class AIModelStats(BaseModel):
    """AI model statistics"""
    total_models: int
    active_models: int
    pending_approval: int
    suspended_models: int
    models_by_type: Dict[str, int]
    models_by_owner: Dict[str, int]
    recent_activity: List[Dict[str, Any]]