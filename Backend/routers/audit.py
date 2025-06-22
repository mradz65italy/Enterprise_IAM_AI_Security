"""
Audit logging and security monitoring endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta

from database.connection import get_db
from database.models import User, UserRole, AccessAction, AuditLevel
from utils.security import get_current_user, require_min_role
from services.audit_service import AuditService
from schemas.audit import AuditLogResponse, AuditLogList, SecurityEventResponse, AuditStats
from loguru import logger

router = APIRouter()
audit_service = AuditService()

@router.get("/logs", response_model=AuditLogList)
async def get_audit_logs(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_id: Optional[int] = None,
    ai_model_id: Optional[int] = None,
    action: Optional[AccessAction] = None,
    resource_type: Optional[str] = None,
    level: Optional[AuditLevel] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ip_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get audit logs with filtering"""
    try:
        # Non-admin users can only see their own logs
        if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
            user_id = current_user.id
        
        logs = await audit_service.get_audit_logs(
            db=db,
            user_id=user_id,
            ai_model_id=ai_model_id,
            action=action,
            resource_type=resource_type,
            level=level,
            start_date=start_date,
            end_date=end_date,
            ip_address=ip_address,
            limit=limit,
            offset=skip
        )
        
        # Log the audit access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="audit",
            description=f"Accessed audit logs (count: {len(logs)})",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return AuditLogList(
            logs=[AuditLogResponse.from_orm(log) for log in logs],
            total=len(logs),
            skip=skip,
            limit=limit
        )
    
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit logs"
        )

@router.get("/security-events", response_model=List[SecurityEventResponse])
async def get_security_events(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get security events"""
    try:
        events = await audit_service.get_security_events(
            db=db,
            event_type=event_type,
            severity=severity,
            resolved=resolved,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=skip
        )
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="security_events",
            description=f"Accessed security events (count: {len(events)})",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return [SecurityEventResponse.from_orm(event) for event in events]
    
    except Exception as e:
        logger.error(f"Error retrieving security events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security events"
        )

@router.get("/statistics", response_model=AuditStats)
async def get_audit_statistics(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get audit statistics"""
    try:
        start_date = datetime.utcnow() - timedelta(days=days)
        end_date = datetime.utcnow()
        
        stats = await audit_service.get_audit_statistics(
            db=db,
            start_date=start_date,
            end_date=end_date
        )
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="audit_statistics",
            description=f"Accessed audit statistics for {days} days",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return AuditStats(**stats)
    
    except Exception as e:
        logger.error(f"Error retrieving audit statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve audit statistics"
        )

@router.get("/suspicious-activity", response_model=List[dict])
async def get_suspicious_activity(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get suspicious activity analysis"""
    try:
        activities = await audit_service.analyze_suspicious_activity(
            db=db,
            lookback_hours=hours
        )
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="suspicious_activity",
            description=f"Accessed suspicious activity analysis for {hours} hours",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return activities
    
    except Exception as e:
        logger.error(f"Error analyzing suspicious activity: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze suspicious activity"
        )

@router.post("/cleanup", response_model=dict)
async def cleanup_old_logs(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.ADMIN))
):
    """Clean up old audit logs based on retention policy"""
    try:
        deleted_count = await audit_service.cleanup_old_audit_logs(db)
        
        # Log the cleanup
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.DELETE,
            resource_type="audit",
            description=f"Cleaned up {deleted_count} old audit logs",
            ip_address=request.client.host,
            metadata={"deleted_count": deleted_count},
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": f"Cleaned up {deleted_count} old audit logs"}
    
    except Exception as e:
        logger.error(f"Error cleaning up audit logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clean up audit logs"
        )