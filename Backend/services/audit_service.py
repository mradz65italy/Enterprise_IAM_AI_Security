"""
Comprehensive audit logging service
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
import json
import uuid

from database.models import (
    AuditLog, SecurityEvent, User, AIModel, 
    AccessAction, AuditLevel
)
from config import settings
from loguru import logger

class AuditService:
    """Audit logging and security event management"""
    
    def __init__(self):
        self.retention_days = settings.AUDIT_RETENTION_DAYS
        self.enable_audit = settings.ENABLE_AUDIT_LOGGING
    
    async def log_audit(
        self,
        db: AsyncSession,
        action: AccessAction,
        resource_type: str,
        description: str,
        user_id: Optional[int] = None,
        ai_model_id: Optional[int] = None,
        resource_id: Optional[str] = None,
        level: AuditLevel = AuditLevel.INFO,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        network_location: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        risk_score: int = 0,
        tags: Optional[List[str]] = None
    ) -> AuditLog:
        """Log an audit event"""
        
        if not self.enable_audit:
            return None
        
        try:
            audit_log = AuditLog(
                uuid=str(uuid.uuid4()),
                user_id=user_id,
                ai_model_id=ai_model_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                description=description,
                level=level,
                ip_address=ip_address,
                user_agent=user_agent,
                network_location=network_location,
                request_id=request_id,
                session_id=session_id,
                endpoint=endpoint,
                method=method,
                metadata=metadata,
                risk_score=risk_score,
                tags=tags,
                timestamp=datetime.utcnow()
            )
            
            db.add(audit_log)
            await db.commit()
            await db.refresh(audit_log)
            
            logger.info(f"Audit log created: {audit_log.uuid} - {description}")
            return audit_log
        
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}")
            await db.rollback()
            return None
    
    async def log_security_event(
        self,
        db: AsyncSession,
        event_type: str,
        severity: str,
        description: str,
        source_ip: Optional[str] = None,
        target_resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """Log a security event"""
        
        try:
            security_event = SecurityEvent(
                event_type=event_type,
                severity=severity,
                source_ip=source_ip,
                target_resource=target_resource,
                description=description,
                details=details,
                resolved=False,
                created_at=datetime.utcnow()
            )
            
            db.add(security_event)
            await db.commit()
            await db.refresh(security_event)
            
            logger.warning(f"Security event: {event_type} - {description}")
            return security_event
        
        except Exception as e:
            logger.error(f"Failed to create security event: {e}")
            await db.rollback()
            return None
    
    async def get_audit_logs(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        ai_model_id: Optional[int] = None,
        action: Optional[AccessAction] = None,
        resource_type: Optional[str] = None,
        level: Optional[AuditLevel] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        ip_address: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        """Retrieve audit logs with filtering"""
        
        try:
            query = select(AuditLog)
            
            # Apply filters
            conditions = []
            
            if user_id:
                conditions.append(AuditLog.user_id == user_id)
            
            if ai_model_id:
                conditions.append(AuditLog.ai_model_id == ai_model_id)
            
            if action:
                conditions.append(AuditLog.action == action)
            
            if resource_type:
                conditions.append(AuditLog.resource_type == resource_type)
            
            if level:
                conditions.append(AuditLog.level == level)
            
            if start_date:
                conditions.append(AuditLog.timestamp >= start_date)
            
            if end_date:
                conditions.append(AuditLog.timestamp <= end_date)
            
            if ip_address:
                conditions.append(AuditLog.ip_address == ip_address)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            query = query.order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)
            
            result = await db.execute(query)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {e}")
            return []
    
    async def get_security_events(
        self,
        db: AsyncSession,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[SecurityEvent]:
        """Retrieve security events with filtering"""
        
        try:
            query = select(SecurityEvent)
            
            conditions = []
            
            if event_type:
                conditions.append(SecurityEvent.event_type == event_type)
            
            if severity:
                conditions.append(SecurityEvent.severity == severity)
            
            if resolved is not None:
                conditions.append(SecurityEvent.resolved == resolved)
            
            if start_date:
                conditions.append(SecurityEvent.created_at >= start_date)
            
            if end_date:
                conditions.append(SecurityEvent.created_at <= end_date)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            query = query.order_by(desc(SecurityEvent.created_at)).limit(limit).offset(offset)
            
            result = await db.execute(query)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to retrieve security events: {e}")
            return []
    
    async def get_audit_statistics(
        self,
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get audit statistics"""
        
        try:
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=30)
            
            if not end_date:
                end_date = datetime.utcnow()
            
            # Total audit logs
            total_logs_result = await db.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.timestamp.between(start_date, end_date)
                )
            )
            total_logs = total_logs_result.scalar()
            
            # Logs by action
            action_stats_result = await db.execute(
                select(AuditLog.action, func.count(AuditLog.id))
                .where(AuditLog.timestamp.between(start_date, end_date))
                .group_by(AuditLog.action)
            )
            action_stats = dict(action_stats_result.fetchall())
            
            # Logs by level
            level_stats_result = await db.execute(
                select(AuditLog.level, func.count(AuditLog.id))
                .where(AuditLog.timestamp.between(start_date, end_date))
                .group_by(AuditLog.level)
            )
            level_stats = dict(level_stats_result.fetchall())
            
            # Top IP addresses
            ip_stats_result = await db.execute(
                select(AuditLog.ip_address, func.count(AuditLog.id))
                .where(
                    and_(
                        AuditLog.timestamp.between(start_date, end_date),
                        AuditLog.ip_address.isnot(None)
                    )
                )
                .group_by(AuditLog.ip_address)
                .order_by(desc(func.count(AuditLog.id)))
                .limit(10)
            )
            top_ips = dict(ip_stats_result.fetchall())
            
            # Security events count
            security_events_result = await db.execute(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.created_at.between(start_date, end_date)
                )
            )
            security_events_count = security_events_result.scalar()
            
            return {
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                },
                "total_audit_logs": total_logs,
                "logs_by_action": {str(k): v for k, v in action_stats.items()},
                "logs_by_level": {str(k): v for k, v in level_stats.items()},
                "top_ip_addresses": top_ips,
                "security_events_count": security_events_count
            }
        
        except Exception as e:
            logger.error(f"Failed to get audit statistics: {e}")
            return {}
    
    async def cleanup_old_audit_logs(self, db: AsyncSession) -> int:
        """Clean up old audit logs based on retention policy"""
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
            
            # Count logs to be deleted
            count_result = await db.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.timestamp < cutoff_date
                )
            )
            count = count_result.scalar()
            
            if count > 0:
                # Delete old logs
                await db.execute(
                    AuditLog.__table__.delete().where(
                        AuditLog.timestamp < cutoff_date
                    )
                )
                await db.commit()
                
                logger.info(f"Cleaned up {count} old audit logs")
            
            return count
        
        except Exception as e:
            logger.error(f"Failed to cleanup old audit logs: {e}")
            await db.rollback()
            return 0
    
    async def analyze_suspicious_activity(
        self,
        db: AsyncSession,
        lookback_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Analyze for suspicious activity patterns"""
        
        try:
            suspicious_activities = []
            cutoff_time = datetime.utcnow() - timedelta(hours=lookback_hours)
            
            # Multiple failed login attempts from same IP
            failed_login_result = await db.execute(
                select(
                    AuditLog.ip_address,
                    func.count(AuditLog.id).label('count')
                )
                .where(
                    and_(
                        AuditLog.action == AccessAction.LOGIN,
                        AuditLog.level == AuditLevel.WARNING,
                        AuditLog.timestamp >= cutoff_time,
                        AuditLog.ip_address.isnot(None)
                    )
                )
                .group_by(AuditLog.ip_address)
                .having(func.count(AuditLog.id) > 5)
            )
            
            for ip, count in failed_login_result.fetchall():
                suspicious_activities.append({
                    "type": "multiple_failed_logins",
                    "ip_address": ip,
                    "count": count,
                    "severity": "high" if count > 10 else "medium"
                })
            
            # Unusual activity patterns (e.g., activity outside business hours)
            unusual_time_result = await db.execute(
                select(
                    AuditLog.user_id,
                    AuditLog.ai_model_id,
                    func.count(AuditLog.id).label('count')
                )
                .where(
                    and_(
                        AuditLog.timestamp >= cutoff_time,
                        func.extract('hour', AuditLog.timestamp).between(22, 6)
                    )
                )
                .group_by(AuditLog.user_id, AuditLog.ai_model_id)
                .having(func.count(AuditLog.id) > 20)
            )
            
            for user_id, ai_model_id, count in unusual_time_result.fetchall():
                suspicious_activities.append({
                    "type": "unusual_time_activity",
                    "user_id": user_id,
                    "ai_model_id": ai_model_id,
                    "count": count,
                    "severity": "medium"
                })
            
            return suspicious_activities
        
        except Exception as e:
            logger.error(f"Failed to analyze suspicious activity: {e}")
            return []