 """
Database models for the Enterprise AI IAM System
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON, Enum, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database.connection import Base
import enum
from datetime import datetime
from typing import Optional, Dict, Any
import uuid

class UserRole(str, enum.Enum):
    """User roles in the system"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    AI_MANAGER = "ai_manager"
    AUDITOR = "auditor"
    VIEWER = "viewer"

class AIModelType(str, enum.Enum):
    """Types of AI models"""
    LANGUAGE_MODEL = "language_model"
    VISION_MODEL = "vision_model"
    AUDIO_MODEL = "audio_model"
    MULTIMODAL = "multimodal"
    EMBEDDING_MODEL = "embedding_model"
    CLASSIFICATION = "classification"
    GENERATION = "generation"
    CUSTOM = "custom"

class AIModelStatus(str, enum.Enum):
    """AI Model status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_APPROVAL = "pending_approval"
    DECOMMISSIONED = "decommissioned"

class AccessAction(str, enum.Enum):
    """Access actions for audit logging"""
    LOGIN = "login"
    LOGOUT = "logout"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    INFERENCE = "inference"
    TRAINING = "training"
    CONFIGURATION = "configuration"

class AuditLevel(str, enum.Enum):
    """Audit log levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class User(Base):
    """User model for human administrators"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(32), nullable=True)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    ai_models = relationship("AIModel", back_populates="owner")
    permissions = relationship("UserPermission", back_populates="user", foreign_keys="UserPermission.user_id")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    __table_args__ = (
        Index("idx_users_role_active", "role", "is_active"),
        Index("idx_users_created", "created_at"),
    )

class AIModel(Base):
    """AI Model identity and registration"""
    __tablename__ = "ai_models"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
    model_id = Column(String(100), unique=True, index=True, nullable=False)  # Unique identifier in network
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    model_type = Column(Enum(AIModelType), nullable=False)
    version = Column(String(50), nullable=False)
    status = Column(Enum(AIModelStatus), default=AIModelStatus.PENDING_APPROVAL, nullable=False)
    
    # Owner and network information
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    network_location = Column(String(255), nullable=False)  # IP address or hostname
    port = Column(Integer, nullable=True)
    endpoint_path = Column(String(255), nullable=True)
    
    # Security and access
    api_key_hash = Column(String(255), nullable=True)  # Hashed API key for model authentication
    certificate_fingerprint = Column(String(255), nullable=True)  # SSL certificate fingerprint
    allowed_operations = Column(JSON, nullable=True)  # List of allowed operations
    resource_limits = Column(JSON, nullable=True)  # Resource consumption limits
    
    # Metadata
    capabilities = Column(JSON, nullable=True)  # Model capabilities and features
    hardware_requirements = Column(JSON, nullable=True)  # Hardware specifications
    compliance_tags = Column(JSON, nullable=True)  # Compliance and regulatory tags
    
    # Timestamps
    last_seen = Column(DateTime, nullable=True)
    last_authenticated = Column(DateTime, nullable=True)
    registration_approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="ai_models")
    permissions = relationship("AIModelPermission", back_populates="ai_model")
    audit_logs = relationship("AuditLog", back_populates="ai_model")
    access_tokens = relationship("AIModelToken", back_populates="ai_model")
    
    __table_args__ = (
        Index("idx_ai_models_status_type", "status", "model_type"),
        Index("idx_ai_models_owner", "owner_id"),
        Index("idx_ai_models_network", "network_location", "port"),
        Index("idx_ai_models_last_seen", "last_seen"),
    )

class Permission(Base):
    """System permissions and capabilities"""
    __tablename__ = "permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    resource_type = Column(String(50), nullable=False)  # users, ai_models, audit, etc.
    action = Column(String(50), nullable=False)  # read, write, delete, execute
    conditions = Column(JSON, nullable=True)  # Additional conditions for permission
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    user_permissions = relationship("UserPermission", back_populates="permission")
    ai_model_permissions = relationship("AIModelPermission", back_populates="permission")

class UserPermission(Base):
    """User permissions mapping"""
    __tablename__ = "user_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Who granted the permission
    granted_at = Column(DateTime, server_default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="permissions", foreign_keys=[user_id])
    permission = relationship("Permission", back_populates="user_permissions")
    granter = relationship("User", foreign_keys=[granted_by])
    
    __table_args__ = (
        Index("idx_user_permissions_active", "user_id", "is_active"),
        Index("idx_user_permissions_expires", "expires_at"),
    )

class AIModelPermission(Base):
    """AI Model permissions mapping"""
    __tablename__ = "ai_model_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    ai_model_id = Column(Integer, ForeignKey("ai_models.id"), nullable=False)
    permission_id = Column(Integer, ForeignKey("permissions.id"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    granted_at = Column(DateTime, server_default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    conditions = Column(JSON, nullable=True)  # Specific conditions for this model
    
    # Relationships
    ai_model = relationship("AIModel", back_populates="permissions")
    permission = relationship("Permission", back_populates="ai_model_permissions")
    granter = relationship("User", foreign_keys=[granted_by])
    
    __table_args__ = (
        Index("idx_ai_model_permissions_active", "ai_model_id", "is_active"),
        Index("idx_ai_model_permissions_expires", "expires_at"),
    )

class AIModelToken(Base):
    """Access tokens for AI models"""
    __tablename__ = "ai_model_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    ai_model_id = Column(Integer, ForeignKey("ai_models.id"), nullable=False)
    token_hash = Column(String(255), unique=True, index=True, nullable=False)
    token_name = Column(String(100), nullable=False)
    scopes = Column(JSON, nullable=True)  # List of allowed scopes
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    ai_model = relationship("AIModel", back_populates="access_tokens")
    
    __table_args__ = (
        Index("idx_tokens_active_expires", "is_active", "expires_at"),
        Index("idx_tokens_last_used", "last_used"),
    )

class AuditLog(Base):
    """Comprehensive audit logging"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), index=True)
    
    # Who performed the action
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ai_model_id = Column(Integer, ForeignKey("ai_models.id"), nullable=True)
    
    # What action was performed
    action = Column(Enum(AccessAction), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(String(100), nullable=True)
    
    # Context information
    description = Column(Text, nullable=False)
    level = Column(Enum(AuditLevel), default=AuditLevel.INFO, nullable=False)
    
    # Network and location information
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(Text, nullable=True)
    network_location = Column(String(255), nullable=True)
    geolocation = Column(JSON, nullable=True)  # Geographic location data
    
    # Request information
    request_id = Column(String(36), nullable=True)
    session_id = Column(String(100), nullable=True)
    endpoint = Column(String(255), nullable=True)
    method = Column(String(10), nullable=True)
    
    # Additional metadata
    audit_metadata = Column(JSON, nullable=True)  # Flexible additional data
    risk_score = Column(Integer, default=0)  # Risk assessment score
    tags = Column(JSON, nullable=True)  # Searchable tags
    
    # Timestamps
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    ai_model = relationship("AIModel", back_populates="audit_logs")
    
    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_action_resource", "action", "resource_type"),
        Index("idx_audit_user_timestamp", "user_id", "timestamp"),
        Index("idx_audit_ai_model_timestamp", "ai_model_id", "timestamp"),
        Index("idx_audit_ip_timestamp", "ip_address", "timestamp"),
        Index("idx_audit_level_timestamp", "level", "timestamp"),
    )

class NetworkLocation(Base):
    """Approved network locations for AI models"""
    __tablename__ = "network_locations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    ip_range = Column(String(50), nullable=False)  # CIDR notation
    location_type = Column(String(50), nullable=False)  # datacenter, office, cloud, etc.
    security_level = Column(String(20), nullable=False)  # high, medium, low
    is_approved = Column(Boolean, default=False, nullable=False)
    compliance_tags = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        Index("idx_network_locations_approved", "is_approved"),
        Index("idx_network_locations_security", "security_level"),
    )

class SecurityEvent(Base):
    """Security events and threats"""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)  # login_failure, suspicious_activity, etc.
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    source_ip = Column(String(45), nullable=True)
    target_resource = Column(String(100), nullable=True)
    description = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Relationships
    resolver = relationship("User", foreign_keys=[resolved_by])
    
    __table_args__ = (
        Index("idx_security_events_severity", "severity", "resolved"),
        Index("idx_security_events_created", "created_at"),
        Index("idx_security_events_source", "source_ip"),
    )
