"""
Pydantic schemas for Audit
"""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from database.models import AccessAction, AuditLevel

class AuditLogResponse(BaseModel):
    """Audit log response schema"""
    id: int
    uuid: str
    user_id: Optional[int]
    ai_model_id: Optional[int]
    action: AccessAction
    resource_type: str
    resource_id: Optional[str]
    description: str
    level: AuditLevel
    ip_address: Optional[str]
    user_agent: Optional[str]
    network_location: Optional[str]
    request_id: Optional[str]
    session_id: Optional[str]
    endpoint: Optional[str]
    method: Optional[str]
    metadata: Optional[Dict[str, Any]]
    risk_score: int
    tags: Optional[List[str]]
    timestamp: datetime

    class Config:
        from_attributes = True

class AuditLogList(BaseModel):
    """Audit log list response"""
    logs: List[AuditLogResponse]
    total: int
    skip: int
    limit: int

class SecurityEventResponse(BaseModel):
    """Security event response schema"""
    id: int
    event_type: str
    severity: str
    source_ip: Optional[str]
    target_resource: Optional[str]
    description: str
    details: Optional[Dict[str, Any]]
    resolved: bool
    resolved_by: Optional[int]
    resolved_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

class AuditStats(BaseModel):
    """Audit statistics response"""
    period: Dict[str, str]
    total_audit_logs: int
    logs_by_action: Dict[str, int]
    logs_by_level: Dict[str, int]
    top_ip_addresses: Dict[str, int]
    security_events_count: int