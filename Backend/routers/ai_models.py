"""
AI Models management endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from typing import List, Optional
from datetime import datetime

from database.connection import get_db
from database.models import AIModel, User, AIModelStatus, AIModelType, AccessAction
from utils.security import (
    get_current_user, require_min_role, get_current_ai_model,
    require_admin, validate_ai_model_access
)
from database.models import UserRole
from services.auth_service import AuthService
from services.audit_service import AuditService
from schemas.ai_models import (
    AIModelCreate, AIModelUpdate, AIModelResponse,
    AIModelList, AIModelDetail, AIModelToken
)
from loguru import logger

router = APIRouter()
auth_service = AuthService()
audit_service = AuditService()

@router.post("/register", response_model=dict)
async def register_ai_model(
    request: Request,
    model_data: AIModelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AI_MANAGER))
):
    """Register a new AI model in the system"""
    try:
        # Check if model_id already exists
        result = await db.execute(
            select(AIModel).where(AIModel.model_id == model_data.model_id)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Model ID already registered"
            )
        
        # Generate API key for the model
        api_key = auth_service.generate_api_key()
        api_key_hash = auth_service.hash_api_key(api_key)
        
        # Create AI model
        ai_model = AIModel(
            model_id=model_data.model_id,
            name=model_data.name,
            description=model_data.description,
            model_type=model_data.model_type,
            version=model_data.version,
            owner_id=current_user.id,
            network_location=model_data.network_location,
            port=model_data.port,
            endpoint_path=model_data.endpoint_path,
            api_key_hash=api_key_hash,
            allowed_operations=model_data.allowed_operations,
            resource_limits=model_data.resource_limits,
            capabilities=model_data.capabilities,
            hardware_requirements=model_data.hardware_requirements,
            compliance_tags=model_data.compliance_tags,
            status=AIModelStatus.PENDING_APPROVAL,
            created_at=datetime.utcnow()
        )
        
        db.add(ai_model)
        await db.commit()
        await db.refresh(ai_model)
        
        # Log the registration
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="ai_models",
            resource_id=str(ai_model.id),
            description=f"AI model registered: {ai_model.model_id}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {
            "message": "AI model registered successfully",
            "model_id": ai_model.id,
            "api_key": api_key,  # Return this once - store securely!
            "status": ai_model.status.value
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI model registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI model registration failed"
        )

@router.get("/", response_model=AIModelList)
async def list_ai_models(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    status_filter: Optional[AIModelStatus] = None,
    model_type_filter: Optional[AIModelType] = None,
    owner_filter: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List AI models with filtering and pagination"""
    try:
        query = select(AIModel).order_by(desc(AIModel.created_at))
        count_query = select(func.count(AIModel.id))
        
        # Apply filters
        conditions = []
        
        # Non-admin users can only see their own models
        if current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
            conditions.append(AIModel.owner_id == current_user.id)
        elif owner_filter:
            conditions.append(AIModel.owner_id == owner_filter)
        
        if status_filter:
            conditions.append(AIModel.status == status_filter)
        
        if model_type_filter:
            conditions.append(AIModel.model_type == model_type_filter)
        
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))
        
        # Get total count
        total_result = await db.execute(count_query)
        total = total_result.scalar()
        
        # Apply pagination
        query = query.offset(skip).limit(limit)
        
        # Execute query
        result = await db.execute(query)
        ai_models = result.scalars().all()
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="ai_models",
            description=f"Listed AI models (count: {len(ai_models)})",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return AIModelList(
            models=[AIModelResponse.from_orm(model) for model in ai_models],
            total=total,
            skip=skip,
            limit=limit
        )
    
    except Exception as e:
        logger.error(f"Error listing AI models: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve AI models"
        )

@router.get("/{model_id}", response_model=AIModelDetail)
async def get_ai_model(
    request: Request,
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed information about a specific AI model"""
    try:
        # Get AI model
        result = await db.execute(select(AIModel).where(AIModel.id == model_id))
        ai_model = result.scalar_one_or_none()
        
        if not ai_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="AI model not found"
            )
        
        # Check access permissions
        if (current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and
            ai_model.owner_id != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this AI model"
            )
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="ai_models",
            resource_id=str(ai_model.id),
            description=f"Accessed AI model details: {ai_model.model_id}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return AIModelDetail.from_orm(ai_model)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving AI model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve AI model"
        )

@router.put("/{model_id}", response_model=dict)
async def update_ai_model(
    request: Request,
    model_id: int,
    model_update: AIModelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_min_role(UserRole.AI_MANAGER))
):
    """Update AI model information"""
    try:
        # Get AI model
        result = await db.execute(select(AIModel).where(AIModel.id == model_id))
        ai_model = result.scalar_one_or_none()
        
        if not ai_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="AI model not found"
            )
        
        # Check ownership or admin rights
        if (current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and
            ai_model.owner_id != current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot update this AI model"
            )
        
        # Update fields
        update_data = model_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(ai_model, field):
                setattr(ai_model, field, value)
        
        ai_model.updated_at = datetime.utcnow()
        await db.commit()
        
        # Log the update
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="ai_models",
            resource_id=str(ai_model.id),
            description=f"Updated AI model: {ai_model.model_id}",
            ip_address=request.client.host,
            metadata={"updated_fields": list(update_data.keys())},
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "AI model updated successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating AI model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update AI model"
        )

@router.post("/{model_id}/approve", response_model=dict)
async def approve_ai_model(
    request: Request,
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Approve AI model for active use"""
    try:
        # Get AI model
        result = await db.execute(select(AIModel).where(AIModel.id == model_id))
        ai_model = result.scalar_one_or_none()
        
        if not ai_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="AI model not found"
            )
        
        if ai_model.status != AIModelStatus.PENDING_APPROVAL:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AI model is not pending approval"
            )
        
        # Approve the model
        ai_model.status = AIModelStatus.ACTIVE
        ai_model.registration_approved_at = datetime.utcnow()
        ai_model.updated_at = datetime.utcnow()
        await db.commit()
        
        # Log the approval
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="ai_models",
            resource_id=str(ai_model.id),
            description=f"Approved AI model: {ai_model.model_id}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "AI model approved successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving AI model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve AI model"
        )

@router.post("/{model_id}/suspend", response_model=dict)
async def suspend_ai_model(
    request: Request,
    model_id: int,
    reason: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Suspend AI model access"""
    try:
        # Get AI model
        result = await db.execute(select(AIModel).where(AIModel.id == model_id))
        ai_model = result.scalar_one_or_none()
        
        if not ai_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="AI model not found"
            )
        
        # Suspend the model
        ai_model.status = AIModelStatus.SUSPENDED
        ai_model.updated_at = datetime.utcnow()
        await db.commit()
        
        # Log the suspension
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="ai_models",
            resource_id=str(ai_model.id),
            description=f"Suspended AI model: {ai_model.model_id}",
            ip_address=request.client.host,
            metadata={"reason": reason},
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "AI model suspended successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error suspending AI model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to suspend AI model"
        )

@router.delete("/{model_id}", response_model=dict)
async def delete_ai_model(
    request: Request,
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete AI model (admin only)"""
    try:
        # Get AI model
        result = await db.execute(select(AIModel).where(AIModel.id == model_id))
        ai_model = result.scalar_one_or_none()
        
        if not ai_model:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="AI model not found"
            )
        
        model_info = {
            "id": ai_model.id,
            "model_id": ai_model.model_id,
            "name": ai_model.name
        }
        
        # Delete the model
        await db.delete(ai_model)
        await db.commit()
        
        # Log the deletion
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.DELETE,
            resource_type="ai_models",
            resource_id=str(model_info["id"]),
            description=f"Deleted AI model: {model_info['model_id']}",
            ip_address=request.client.host,
            metadata=model_info,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "AI model deleted successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting AI model: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete AI model"
        )

@router.post("/{model_id}/heartbeat", response_model=dict)
async def ai_model_heartbeat(
    request: Request,
    model_id: int,
    db: AsyncSession = Depends(get_db),
    current_ai_model: AIModel = Depends(get_current_ai_model)
):
    """AI model heartbeat endpoint"""
    try:
        # Verify the model ID matches
        if current_ai_model.id != model_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Model ID mismatch"
            )
        
        # Update last seen timestamp
        current_ai_model.last_seen = datetime.utcnow()
        await db.commit()
        
        # Log the heartbeat (low priority)
        await audit_service.log_audit(
            db=db,
            ai_model_id=current_ai_model.id,
            action=AccessAction.READ,
            resource_type="ai_models",
            resource_id=str(current_ai_model.id),
            description=f"Heartbeat from AI model: {current_ai_model.model_id}",
            ip_address=request.client.host,
            level="info",
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "model_status": current_ai_model.status.value
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Heartbeat failed"
        )