 """
User management endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc
from typing import List, Optional
from datetime import datetime

from database.connection import get_db
from database.models import User, UserRole, AccessAction
from utils.security import get_current_user, require_admin, require_super_admin
from services.auth_service import AuthService
from services.audit_service import AuditService
from schemas.users import UserCreate, UserUpdate, UserResponse, UserList, UserDetail
from loguru import logger

router = APIRouter()
auth_service = AuthService()
audit_service = AuditService()

@router.post("/", response_model=dict)
async def create_user(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new user (admin only)"""
    try:
        # Check if username already exists
        result = await db.execute(select(User).where(User.username == user_data.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Check if email already exists
        result = await db.execute(select(User).where(User.email == user_data.email))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already exists"
            )
        
        # Only super admin can create admin users
        if (user_data.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and 
            current_user.role != UserRole.SUPER_ADMIN):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only super admin can create admin users"
            )
        
        # Create user
        user = await auth_service.create_user(
            db=db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=user_data.role
        )
        
        # Log user creation
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="users",
            resource_id=str(user.id),
            description=f"Created user: {user.username}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User created successfully", "user_id": user.id}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User creation failed"
        )

@router.get("/", response_model=UserList)
async def list_users(
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    role_filter: Optional[UserRole] = None,
    active_filter: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """List users with filtering and pagination"""
    try:
        query = select(User).order_by(desc(User.created_at))
        count_query = select(func.count(User.id))
        
        # Apply filters
        conditions = []
        
        if role_filter:
            conditions.append(User.role == role_filter)
        
        if active_filter is not None:
            conditions.append(User.is_active == active_filter)
        
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
        users = result.scalars().all()
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="users",
            description=f"Listed users (count: {len(users)})",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return UserList(
            users=[UserResponse.from_orm(user) for user in users],
            total=total,
            skip=skip,
            limit=limit
        )
    
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.get("/{user_id}", response_model=UserDetail)
async def get_user(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get user details"""
    try:
        # Users can only view their own details unless they're admin
        if (current_user.id != user_id and 
            current_user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Get user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Log the access
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.READ,
            resource_type="users",
            resource_id=str(user.id),
            description=f"Accessed user details: {user.username}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return UserDetail.from_orm(user)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )

@router.put("/{user_id}", response_model=dict)
async def update_user(
    request: Request,
    user_id: int,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user information"""
    try:
        # Get target user
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Permission checks
        is_self_update = current_user.id == user_id
        is_admin = current_user.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]
        
        if not (is_self_update or is_admin):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Role change restrictions
        if user_update.role is not None:
            if not is_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only admins can change user roles"
                )
            
            # Only super admin can change admin roles
            if (user_update.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN] and
                current_user.role != UserRole.SUPER_ADMIN):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only super admin can assign admin roles"
                )
        
        # Update fields
        update_data = user_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(user, field):
                setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        await db.commit()
        
        # Log the update
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="users",
            resource_id=str(user.id),
            description=f"Updated user: {user.username}",
            ip_address=request.client.host,
            metadata={"updated_fields": list(update_data.keys())},
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User updated successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@router.post("/{user_id}/activate", response_model=dict)
async def activate_user(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Activate user account"""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        user.is_active = True
        user.updated_at = datetime.utcnow()
        await db.commit()
        
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="users",
            resource_id=str(user.id),
            description=f"Activated user: {user.username}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User activated successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user"
        )

@router.post("/{user_id}/deactivate", response_model=dict)
async def deactivate_user(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Deactivate user account"""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent deactivating super admin
        if user.role == UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate super admin"
            )
        
        user.is_active = False
        user.updated_at = datetime.utcnow()
        await db.commit()
        
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.WRITE,
            resource_type="users",
            resource_id=str(user.id),
            description=f"Deactivated user: {user.username}",
            ip_address=request.client.host,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User deactivated successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deactivating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user"
        )

@router.delete("/{user_id}", response_model=dict)
async def delete_user(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_super_admin)
):
    """Delete user (super admin only)"""
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent deleting super admin
        if user.role == UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete super admin"
            )
        
        user_info = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value
        }
        
        await db.delete(user)
        await db.commit()
        
        await audit_service.log_audit(
            db=db,
            user_id=current_user.id,
            action=AccessAction.DELETE,
            resource_type="users",
            resource_id=str(user_info["id"]),
            description=f"Deleted user: {user_info['username']}",
            ip_address=request.client.host,
            metadata=user_info,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        return {"message": "User deleted successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )
