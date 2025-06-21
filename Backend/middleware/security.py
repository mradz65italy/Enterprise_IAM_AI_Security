 ""
Security middleware for the Enterprise AI IAM System
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time
import hashlib
from loguru import logger
from typing import Dict, Set
import asyncio
from datetime import datetime, timedelta

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware with rate limiting, IP filtering, and security headers"""
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit_store: Dict[str, Dict] = {}
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Dict[str, Dict] = {}
        
        # Start cleanup task
        asyncio.create_task(self.cleanup_task())
    
    async def dispatch(self, request: Request, call_next):
        """Process request through security middleware"""
        start_time = time.time()
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            logger.warning(f"Blocked IP attempted access: {client_ip}")
            return Response(
                content="Access denied",
                status_code=403,
                headers={"X-Blocked-Reason": "IP-Blocked"}
            )
        
        # Rate limiting
        if not await self.check_rate_limit(client_ip, request):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return Response(
                content="Rate limit exceeded",
                status_code=429,
                headers={
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Window": "60",
                    "Retry-After": "60"
                }
            )
        
        # Process request
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Add security headers
        self.add_security_headers(response)
        
        # Monitor for suspicious activity
        await self.monitor_suspicious_activity(client_ip, request, response)
        
        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address with proxy support"""
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",  # Cloudflare
            "X-Client-IP"
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip:
                    return ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    async def check_rate_limit(self, client_ip: str, request: Request) -> bool:
        """Check if request is within rate limits"""
        current_time = time.time()
        window_size = 60  # 60 seconds
        max_requests = 100
        
        # Clean up old entries
        if client_ip in self.rate_limit_store:
            self.rate_limit_store[client_ip]["requests"] = [
                req_time for req_time in self.rate_limit_store[client_ip]["requests"]
                if current_time - req_time < window_size
            ]
        else:
            self.rate_limit_store[client_ip] = {"requests": []}
        
        # Check if limit exceeded
        if len(self.rate_limit_store[client_ip]["requests"]) >= max_requests:
            # Mark as suspicious if repeatedly hitting rate limits
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = {
                    "first_seen": current_time,
                    "rate_limit_violations": 1
                }
            else:
                self.suspicious_ips[client_ip]["rate_limit_violations"] += 1
                
                # Block IP if too many violations
                if self.suspicious_ips[client_ip]["rate_limit_violations"] > 5:
                    self.blocked_ips.add(client_ip)
                    logger.critical(f"IP blocked due to repeated rate limit violations: {client_ip}")
            
            return False
        
        # Add request to store
        self.rate_limit_store[client_ip]["requests"].append(current_time)
        return True
    
    def add_security_headers(self, response: Response):
        """Add security headers to response"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
    
    async def monitor_suspicious_activity(self, client_ip: str, request: Request, response: Response):
        """Monitor for suspicious activity patterns"""
        current_time = time.time()
        
        # Monitor for authentication failures
        if (request.url.path.endswith('/login') or 
            request.url.path.endswith('/authenticate')) and response.status_code == 401:
            
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = {
                    "first_seen": current_time,
                    "auth_failures": 1
                }
            else:
                self.suspicious_ips[client_ip]["auth_failures"] = (
                    self.suspicious_ips[client_ip].get("auth_failures", 0) + 1
                )
            
            # Block IP after multiple authentication failures
            if self.suspicious_ips[client_ip]["auth_failures"] > 10:
                self.blocked_ips.add(client_ip)
                logger.critical(f"IP blocked due to repeated authentication failures: {client_ip}")
        
        # Monitor for scanning activity (multiple 404s)
        if response.status_code == 404:
            key = f"{client_ip}_404"
            if key not in self.suspicious_ips:
                self.suspicious_ips[key] = {
                    "first_seen": current_time,
                    "not_found_count": 1
                }
            else:
                self.suspicious_ips[key]["not_found_count"] += 1
            
            # Flag as suspicious if too many 404s
            if self.suspicious_ips[key]["not_found_count"] > 20:
                self.blocked_ips.add(client_ip)
                logger.critical(f"IP blocked due to scanning activity: {client_ip}")
    
    async def cleanup_task(self):
        """Periodic cleanup of stored data"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                current_time = time.time()
                
                # Clean up rate limit store
                for ip in list(self.rate_limit_store.keys()):
                    self.rate_limit_store[ip]["requests"] = [
                        req_time for req_time in self.rate_limit_store[ip]["requests"]
                        if current_time - req_time < 3600  # Keep for 1 hour
                    ]
                    
                    if not self.rate_limit_store[ip]["requests"]:
                        del self.rate_limit_store[ip]
                
                # Clean up suspicious IPs (remove entries older than 24 hours)
                for key in list(self.suspicious_ips.keys()):
                    if current_time - self.suspicious_ips[key]["first_seen"] > 86400:
                        del self.suspicious_ips[key]
                
                logger.debug("Security middleware cleanup completed")
                
            except Exception as e:
                logger.error(f"Security middleware cleanup error: {e}")
    
    def get_security_stats(self) -> Dict:
        """Get current security statistics"""
        return {
            "blocked_ips": len(self.blocked_ips),
            "suspicious_ips": len(self.suspicious_ips),
            "rate_limited_ips": len(self.rate_limit_store),
            "blocked_ip_list": list(self.blocked_ips)
        }""
Security middleware for the Enterprise AI IAM System
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import time
import hashlib
from loguru import logger
from typing import Dict, Set
import asyncio
from datetime import datetime, timedelta

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware with rate limiting, IP filtering, and security headers"""
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit_store: Dict[str, Dict] = {}
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Dict[str, Dict] = {}
        
        # Start cleanup task
        asyncio.create_task(self.cleanup_task())
    
    async def dispatch(self, request: Request, call_next):
        """Process request through security middleware"""
        start_time = time.time()
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            logger.warning(f"Blocked IP attempted access: {client_ip}")
            return Response(
                content="Access denied",
                status_code=403,
                headers={"X-Blocked-Reason": "IP-Blocked"}
            )
        
        # Rate limiting
        if not await self.check_rate_limit(client_ip, request):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return Response(
                content="Rate limit exceeded",
                status_code=429,
                headers={
                    "X-RateLimit-Limit": "100",
                    "X-RateLimit-Window": "60",
                    "Retry-After": "60"
                }
            )
        
        # Process request
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Add security headers
        self.add_security_headers(response)
        
        # Monitor for suspicious activity
        await self.monitor_suspicious_activity(client_ip, request, response)
        
        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address with proxy support"""
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",  # Cloudflare
            "X-Client-IP"
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip:
                    return ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    async def check_rate_limit(self, client_ip: str, request: Request) -> bool:
        """Check if request is within rate limits"""
        current_time = time.time()
        window_size = 60  # 60 seconds
        max_requests = 100
        
        # Clean up old entries
        if client_ip in self.rate_limit_store:
            self.rate_limit_store[client_ip]["requests"] = [
                req_time for req_time in self.rate_limit_store[client_ip]["requests"]
                if current_time - req_time < window_size
            ]
        else:
            self.rate_limit_store[client_ip] = {"requests": []}
        
        # Check if limit exceeded
        if len(self.rate_limit_store[client_ip]["requests"]) >= max_requests:
            # Mark as suspicious if repeatedly hitting rate limits
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = {
                    "first_seen": current_time,
                    "rate_limit_violations": 1
                }
            else:
                self.suspicious_ips[client_ip]["rate_limit_violations"] += 1
                
                # Block IP if too many violations
                if self.suspicious_ips[client_ip]["rate_limit_violations"] > 5:
                    self.blocked_ips.add(client_ip)
                    logger.critical(f"IP blocked due to repeated rate limit violations: {client_ip}")
            
            return False
        
        # Add request to store
        self.rate_limit_store[client_ip]["requests"].append(current_time)
        return True
    
    def add_security_headers(self, response: Response):
        """Add security headers to response"""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
    
    async def monitor_suspicious_activity(self, client_ip: str, request: Request, response: Response):
        """Monitor for suspicious activity patterns"""
        current_time = time.time()
        
        # Monitor for authentication failures
        if (request.url.path.endswith('/login') or 
            request.url.path.endswith('/authenticate')) and response.status_code == 401:
            
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = {
                    "first_seen": current_time,
                    "auth_failures": 1
                }
            else:
                self.suspicious_ips[client_ip]["auth_failures"] = (
                    self.suspicious_ips[client_ip].get("auth_failures", 0) + 1
                )
            
            # Block IP after multiple authentication failures
            if self.suspicious_ips[client_ip]["auth_failures"] > 10:
                self.blocked_ips.add(client_ip)
                logger.critical(f"IP blocked due to repeated authentication failures: {client_ip}")
        
        # Monitor for scanning activity (multiple 404s)
        if response.status_code == 404:
            key = f"{client_ip}_404"
            if key not in self.suspicious_ips:
                self.suspicious_ips[key] = {
                    "first_seen": current_time,
                    "not_found_count": 1
                }
            else:
                self.suspicious_ips[key]["not_found_count"] += 1
            
            # Flag as suspicious if too many 404s
            if self.suspicious_ips[key]["not_found_count"] > 20:
                self.blocked_ips.add(client_ip)
                logger.critical(f"IP blocked due to scanning activity: {client_ip}")
    
    async def cleanup_task(self):
        """Periodic cleanup of stored data"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                current_time = time.time()
                
                # Clean up rate limit store
                for ip in list(self.rate_limit_store.keys()):
                    self.rate_limit_store[ip]["requests"] = [
                        req_time for req_time in self.rate_limit_store[ip]["requests"]
                        if current_time - req_time < 3600  # Keep for 1 hour
                    ]
                    
                    if not self.rate_limit_store[ip]["requests"]:
                        del self.rate_limit_store[ip]
                
                # Clean up suspicious IPs (remove entries older than 24 hours)
                for key in list(self.suspicious_ips.keys()):
                    if current_time - self.suspicious_ips[key]["first_seen"] > 86400:
                        del self.suspicious_ips[key]
                
                logger.debug("Security middleware cleanup completed")
                
            except Exception as e:
                logger.error(f"Security middleware cleanup error: {e}")
    
    def get_security_stats(self) -> Dict:
        """Get current security statistics"""
        return {
            "blocked_ips": len(self.blocked_ips),
            "suspicious_ips": len(self.suspicious_ips),
            "rate_limited_ips": len(self.rate_limit_store),
            "blocked_ip_list": list(self.blocked_ips)
        }
