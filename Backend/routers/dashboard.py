"""
Dashboard and analytics endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from typing import Dict, Any, List
from datetime import datetime, timedelta

from database.connection import get_db
from database.models import (
    User, AIModel, AuditLog, SecurityEvent, UserRole, 
    AIModelStatus, AIModelType, AccessAction, AuditLevel
)
from utils.security import get_current_user, require_min_role
from services.audit_service import AuditService
from loguru import logger

router = APIRouter()
audit_service = AuditService()

@router.get("/overview", response_model=Dict[str, Any])
async def get_dashboard_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard overview statistics"""
    try:
        # Get current time
        now = datetime.utcnow()
        
        # Total users
        total_users_result = await db.execute(select(func.count(User.id)))
        total_users = total_users_result.scalar()
        
        # Active users
        active_users_result = await db.execute(
            select(func.count(User.id)).where(User.is_active == True)
        )
        active_users = active_users_result.scalar()
        
        # Total AI models
        total_models_result = await db.execute(select(func.count(AIModel.id)))
        total_models = total_models_result.scalar()
        
        # Active AI models
        active_models_result = await db.execute(
            select(func.count(AIModel.id)).where(AIModel.status == AIModelStatus.ACTIVE)
        )
        active_models = active_models_result.scalar()
        
        # Pending approval models
        pending_models_result = await db.execute(
            select(func.count(AIModel.id)).where(AIModel.status == AIModelStatus.PENDING_APPROVAL)
        )
        pending_models = pending_models_result.scalar()
        
        # Recent audit events (last 24 hours)
        recent_audit_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.timestamp >= now - timedelta(hours=24)
            )
        )
        recent_audit_count = recent_audit_result.scalar()
        
        # Security events (last 7 days)
        security_events_result = await db.execute(
            select(func.count(SecurityEvent.id)).where(
                and_(
                    SecurityEvent.created_at >= now - timedelta(days=7),
                    SecurityEvent.resolved == False
                )
            )
        )
        security_events_count = security_events_result.scalar()
        
        # AI models by type
        models_by_type_result = await db.execute(
            select(AIModel.model_type, func.count(AIModel.id))
            .where(AIModel.status == AIModelStatus.ACTIVE)
            .group_by(AIModel.model_type)
        )
        models_by_type = {str(k): v for k, v in models_by_type_result.fetchall()}
        
        # Users by role
        users_by_role_result = await db.execute(
            select(User.role, func.count(User.id))
            .where(User.is_active == True)
            .group_by(User.role)
        )
        users_by_role = {str(k): v for k, v in users_by_role_result.fetchall()}
        
        # Recent logins (last 24 hours)
        recent_logins_result = await db.execute(
            select(func.count(AuditLog.id)).where(
                and_(
                    AuditLog.action == AccessAction.LOGIN,
                    AuditLog.timestamp >= now - timedelta(hours=24)
                )
            )
        )
        recent_logins = recent_logins_result.scalar()
        
        # System health indicators
        health_indicators = {
            "database_healthy": True,  # Since we're querying successfully
            "total_users": total_users,
            "active_users": active_users,
            "total_ai_models": total_models,
            "active_ai_models": active_models,
            "pending_approvals": pending_models,
            "recent_activity": recent_audit_count,
            "security_alerts": security_events_count,
            "recent_logins": recent_logins
        }
        
        # Log the dashboard access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="dashboard",
            description="Accessed dashboard overview",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {
            "overview": {
                "total_users": total_users,
                "active_users": active_users,
                "total_ai_models": total_models,
                "active_ai_models": active_models,
                "pending_approvals": pending_models,
                "recent_audit_events": recent_audit_count,
                "security_events": security_events_count,
                "recent_logins": recent_logins
            },
            "breakdowns": {
                "models_by_type": models_by_type,
                "users_by_role": users_by_role
            },
            "health_indicators": health_indicators,
            "timestamp": now.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error retrieving dashboard overview: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard data"
        )

@router.get("/activity", response_model=List[Dict[str, Any]])
async def get_recent_activity(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get recent activity for dashboard"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get recent audit logs
        query = select(AuditLog).where(
            AuditLog.timestamp >= cutoff_time
        ).order_by(desc(AuditLog.timestamp)).limit(limit)
        
        result = await db.execute(query)
        logs = result.scalars().all()
        
        activities = []
        for log in logs:
            activity = {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "action": log.action.value,
                "resource_type": log.resource_type,
                "description": log.description,
                "level": log.level.value,
                "ip_address": log.ip_address,
                "user_id": log.user_id,
                "ai_model_id": log.ai_model_id,
                "risk_score": log.risk_score
            }
            activities.append(activity)
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="dashboard_activity",
            description=f"Retrieved recent activity for {hours} hours",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return activities
    
    except Exception as e:
        logger.error(f"Error retrieving recent activity: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve recent activity"
        )

@router.get("/security-alerts", response_model=List[Dict[str, Any]])
async def get_security_alerts(
    request: Request,
    days: int = Query(7, ge=1, le=30),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AUDITOR))
):
    """Get security alerts for dashboard"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        
        # Get unresolved security events
        query = select(SecurityEvent).where(
            and_(
                SecurityEvent.created_at >= cutoff_time,
                SecurityEvent.resolved == False
            )
        ).order_by(desc(SecurityEvent.created_at)).limit(limit)
        
        result = await db.execute(query)
        events = result.scalars().all()
        
        alerts = []
        for event in events:
            alert = {
                "id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "source_ip": event.source_ip,
                "target_resource": event.target_resource,
                "created_at": event.created_at.isoformat(),
                "details": event.details
            }
            alerts.append(alert)
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="security_alerts",
            description=f"Retrieved security alerts for {days} days",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return alerts
    
    except Exception as e:
        logger.error(f"Error retrieving security alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security alerts"
        )

@router.get("/ai-models/status", response_model=Dict[str, Any])
async def get_ai_models_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AI_MANAGER))
):
    """Get AI models status summary"""
    try:
        # Models by status
        status_result = await db.execute(
            select(AIModel.status, func.count(AIModel.id))
            .group_by(AIModel.status)
        )
        models_by_status = {str(k): v for k, v in status_result.fetchall()}
        
        # Models by type
        type_result = await db.execute(
            select(AIModel.model_type, func.count(AIModel.id))
            .group_by(AIModel.model_type)
        )
        models_by_type = {str(k): v for k, v in type_result.fetchall()}
        
        # Recently active models (last 24 hours)
        recent_active_result = await db.execute(
            select(func.count(AIModel.id)).where(
                AIModel.last_seen >= datetime.utcnow() - timedelta(hours=24)
            )
        )
        recently_active = recent_active_result.scalar()
        
        # Models needing approval
        pending_approval_result = await db.execute(
            select(AIModel.id, AIModel.model_id, AIModel.name, AIModel.created_at)
            .where(AIModel.status == AIModelStatus.PENDING_APPROVAL)
            .order_by(AIModel.created_at)
        )
        pending_models = [
            {
                "id": model.id,
                "model_id": model.model_id,
                "name": model.name,
                "created_at": model.created_at.isoformat()
            }
            for model in pending_approval_result.fetchall()
        ]
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="ai_models_status",
            description="Retrieved AI models status summary",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {
            "models_by_status": models_by_status,
            "models_by_type": models_by_type,
            "recently_active": recently_active,
            "pending_approval": pending_models,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error retrieving AI models status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve AI models status"
        )