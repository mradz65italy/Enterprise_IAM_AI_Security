"""
Permissions management endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from database.connection import get_db
from database.models import User, UserRole, Permission, UserPermission, AIModelPermission, AccessAction
from utils.security import get_current_user, require_admin
from services.audit_service import AuditService
from loguru import logger

router = APIRouter()
audit_service = AuditService()

@router.get("/", response_model=List[dict])
async def list_permissions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """List all available permissions"""
    try:
        result = await db.execute(select(Permission).order_by(Permission.name))
        permissions = result.scalars().all()
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="permissions",
            description="Listed all permissions",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return [
            {
                "id": perm.id,
                "name": perm.name,
                "description": perm.description,
                "resource_type": perm.resource_type,
                "action": perm.action,
                "conditions": perm.conditions
            }
            for perm in permissions
        ]
    
    except Exception as e:
        logger.error(f"Error listing permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve permissions"
        )

@router.get("/user/{user_id}", response_model=List[dict])
async def get_user_permissions(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Get permissions for a specific user"""
    try:
        # Get user permissions with permission details
        query = select(UserPermission, Permission).join(Permission).where(
            UserPermission.user_id == user_id,
            UserPermission.is_active == True
        )
        result = await db.execute(query)
        user_permissions = result.fetchall()
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="user_permissions",
            resource_id=str(user_id),
            description=f"Retrieved permissions for user ID {user_id}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return [
            {
                "permission_id": perm.id,
                "name": perm.name,
                "description": perm.description,
                "resource_type": perm.resource_type,
                "action": perm.action,
                "granted_at": user_perm.granted_at,
                "expires_at": user_perm.expires_at,
                "granted_by": user_perm.granted_by
            }
            for user_perm, perm in user_permissions
        ]
    
    except Exception as e:
        logger.error(f"Error retrieving user permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user permissions"
        )

@router.get("/ai-model/{model_id}", response_model=List[dict])
async def get_ai_model_permissions(
    request: Request,
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Get permissions for a specific AI model"""
    try:
        # Get AI model permissions with permission details
        query = select(AIModelPermission, Permission).join(Permission).where(
            AIModelPermission.ai_model_id == model_id,
            AIModelPermission.is_active == True
        )
        result = await db.execute(query)
        model_permissions = result.fetchall()
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="ai_model_permissions",
            resource_id=str(model_id),
            description=f"Retrieved permissions for AI model ID {model_id}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return [
            {
                "permission_id": perm.id,
                "name": perm.name,
                "description": perm.description,
                "resource_type": perm.resource_type,
                "action": perm.action,
                "granted_at": model_perm.granted_at,
                "expires_at": model_perm.expires_at,
                "granted_by": model_perm.granted_by,
                "conditions": model_perm.conditions
            }
            for model_perm, perm in model_permissions
        ]
    
    except Exception as e:
        logger.error(f"Error retrieving AI model permissions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve AI model permissions"
        )