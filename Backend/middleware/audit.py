 """
Audit middleware for comprehensive request logging
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time
import json
from loguru import logger
from database.connection import AsyncSessionLocal
from services.audit_service import AuditService
from database.models import AccessAction, AuditLevel
import asyncio

class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware for auditing all requests and responses"""
    
    def __init__(self, app):
        super().__init__(app)
        self.audit_service = AuditService()
    
    async def dispatch(self, request: Request, call_next):
        """Audit request and response"""
        start_time = time.time()
        
        # Extract request information
        request_info = await self.extract_request_info(request)
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Extract response information
        response_info = self.extract_response_info(response, process_time)
        
        # Log audit asynchronously (don't block the response)
        asyncio.create_task(
            self.log_request_audit(request_info, response_info)
        )
        
        return response
    
    async def extract_request_info(self, request: Request) -> dict:
        """Extract relevant information from request"""
        try:
            # Basic request info
            info = {
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": dict(request.headers),
                "client_ip": self.get_client_ip(request),
                "user_agent": request.headers.get("user-agent"),
                "timestamp": time.time(),
                "request_id": getattr(request.state, 'request_id', None)
            }
            
            # Try to get body for POST/PUT requests (but be careful with large payloads)
            if request.method in ["POST", "PUT", "PATCH"]:
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    try:
                        # Read body if it's not too large
                        body = await request.body()
                        if len(body) < 10000:  # Only log bodies smaller than 10KB
                            info["body"] = json.loads(body.decode())
                        else:
                            info["body"] = {"_note": "Body too large to log"}
                    except Exception:
                        info["body"] = {"_error": "Could not parse body"}
            
            return info
        
        except Exception as e:
            logger.error(f"Error extracting request info: {e}")
            return {"error": "Could not extract request info"}
    
    def extract_response_info(self, response: Response, process_time: float) -> dict:
        """Extract relevant information from response"""
        try:
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "process_time": process_time,
                "timestamp": time.time()
            }
        except Exception as e:
            logger.error(f"Error extracting response info: {e}")
            return {"error": "Could not extract response info", "process_time": process_time}
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        forwarded_headers = ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip:
                    return ip
        
        return request.client.host if request.client else "unknown"
    
    async def log_request_audit(self, request_info: dict, response_info: dict):
        """Log audit information to database"""
        try:
            async with AsyncSessionLocal() as db:
                # Determine action based on method and path
                action = self.determine_action(request_info["method"], request_info["path"])
                
                # Determine resource type
                resource_type = self.determine_resource_type(request_info["path"])
                
                # Determine audit level based on response status
                level = self.determine_audit_level(response_info["status_code"])
                
                # Create description
                description = f"{request_info['method']} {request_info['path']} - {response_info['status_code']}"
                
                # Prepare metadata
                metadata = {
                    "request": {
                        "method": request_info["method"],
                        "path": request_info["path"],
                        "query_params": request_info.get("query_params", {}),
                        "user_agent": request_info.get("user_agent"),
                        "content_type": request_info.get("headers", {}).get("content-type")
                    },
                    "response": {
                        "status_code": response_info["status_code"],
                        "process_time": response_info["process_time"]
                    }
                }
                
                # Calculate risk score
                risk_score = self.calculate_risk_score(request_info, response_info)
                
                # Extract user/ai_model info from JWT if available
                user_id, ai_model_id = await self.extract_identity_info(request_info)
                
                # Log the audit
                await self.audit_service.log_audit(
                    db=db,
                    user_id=user_id,
                    ai_model_id=ai_model_id,
                    action=action,
                    resource_type=resource_type,
                    description=description,
                    level=level,
                    ip_address=request_info["client_ip"],
                    user_agent=request_info.get("user_agent"),
                    request_id=request_info.get("request_id"),
                    endpoint=request_info["path"],
                    method=request_info["method"],
                    metadata=metadata,
                    risk_score=risk_score
                )
        
        except Exception as e:
            logger.error(f"Failed to log audit: {e}")
    
    def determine_action(self, method: str, path: str) -> AccessAction:
        """Determine the action type based on method and path"""
        if "login" in path or "authenticate" in path:
            return AccessAction.LOGIN
        elif "logout" in path:
            return AccessAction.LOGOUT
        elif method == "GET":
            return AccessAction.READ
        elif method in ["POST", "PUT", "PATCH"]:
            return AccessAction.WRITE
        elif method == "DELETE":
            return AccessAction.DELETE
        elif "inference" in path or "predict" in path:
            return AccessAction.INFERENCE
        elif "config" in path:
            return AccessAction.CONFIGURATION
        else:
            return AccessAction.READ
    
    def determine_resource_type(self, path: str) -> str:
        """Determine resource type from path"""
        if "/users" in path:
            return "users"
        elif "/ai-models" in path:
            return "ai_models"
        elif "/auth" in path:
            return "authentication"
        elif "/audit" in path:
            return "audit"
        elif "/permissions" in path:
            return "permissions"
        elif "/dashboard" in path:
            return "dashboard"
        else:
            return "api"
    
    def determine_audit_level(self, status_code: int) -> AuditLevel:
        """Determine audit level based on response status code"""
        if status_code >= 500:
            return AuditLevel.CRITICAL
        elif status_code >= 400:
            return AuditLevel.ERROR
        elif status_code >= 300:
            return AuditLevel.WARNING
        else:
            return AuditLevel.INFO
    
    def calculate_risk_score(self, request_info: dict, response_info: dict) -> int:
        """Calculate risk score for the request"""
        risk_score = 0
        
        # High risk for authentication failures
        if "auth" in request_info["path"] and response_info["status_code"] == 401:
            risk_score += 30
        
        # Medium risk for server errors
        if response_info["status_code"] >= 500:
            risk_score += 20
        
        # Low risk for client errors
        if 400 <= response_info["status_code"] < 500:
            risk_score += 10
        
        # High risk for sensitive operations
        sensitive_paths = ["/users", "/permissions", "/ai-models"]
        if any(path in request_info["path"] for path in sensitive_paths):
            if request_info["method"] in ["POST", "PUT", "DELETE"]:
                risk_score += 15
        
        # Risk for unusual response times
        if response_info["process_time"] > 5.0:
            risk_score += 10
        
        return min(risk_score, 100)
    
    async def extract_identity_info(self, request_info: dict) -> tuple:
        """Extract user ID and AI model ID from JWT token"""
        try:
            auth_header = request_info.get("headers", {}).get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return None, None
            
            return None, None
        
        except Exception:
            return None, None
