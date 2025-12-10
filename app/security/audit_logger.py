"""
Audit Logging System - Separate Database
Logs all critical security events for compliance and monitoring
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
import os
import json

# Separate database for audit logs
AUDIT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'audit_logs.db')
AUDIT_DB_URI = f'sqlite:///{AUDIT_DB_PATH}'

# Create separate engine for audit logs
audit_engine = create_engine(AUDIT_DB_URI, echo=False)
AuditBase = declarative_base()
AuditSession = scoped_session(sessionmaker(bind=audit_engine))


class AuditLog(AuditBase):
    """
    Audit log model for security events
    """
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Event information
    event_type = Column(String(50), nullable=False, index=True)  # login, logout, data_access, data_modify, etc.
    event_category = Column(String(50), nullable=False, index=True)  # authentication, authorization, data_access, etc.
    severity = Column(String(20), nullable=False)  # info, warning, error, critical
    
    # User information
    user_id = Column(Integer, index=True)  # null for anonymous attempts
    username = Column(String(80), index=True)
    user_role = Column(String(50))
    
    # Request information
    ip_address = Column(String(45), index=True)  # IPv4 or IPv6
    user_agent = Column(String(255))
    endpoint = Column(String(255))
    method = Column(String(10))
    
    # Event details
    description = Column(Text, nullable=False)
    details = Column(Text)  # JSON string with additional details
    
    # Status
    success = Column(String(10), nullable=False)  # 'success', 'failure', 'blocked'
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.event_type} by {self.username} at {self.timestamp}>'


# Create audit log table
AuditBase.metadata.create_all(audit_engine)


class AuditLogger:
    """
    Audit logging service
    """
    
    # Event types
    LOGIN_ATTEMPT = 'login_attempt'
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILURE = 'login_failure'
    LOGOUT = 'logout'
    REGISTER = 'register'
    PASSWORD_CHANGE = 'password_change'
    ACCOUNT_LOCKED = 'account_locked'
    
    DATA_ACCESS = 'data_access'
    DATA_CREATE = 'data_create'
    DATA_UPDATE = 'data_update'
    DATA_DELETE = 'data_delete'
    
    PERMISSION_DENIED = 'permission_denied'
    INVALID_INPUT = 'invalid_input'
    RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded'
    
    FILE_UPLOAD = 'file_upload'
    FILE_DOWNLOAD = 'file_download'
    
    PREDICTION_CREATE = 'prediction_create'
    APPOINTMENT_CREATE = 'appointment_create'
    APPOINTMENT_UPDATE = 'appointment_update'
    
    USER_CREATE = 'user_create'
    USER_UPDATE = 'user_update'
    USER_DELETE = 'user_delete'
    USER_ACTIVATE = 'user_activate'
    USER_DEACTIVATE = 'user_deactivate'
    
    # Categories
    AUTHENTICATION = 'authentication'
    AUTHORIZATION = 'authorization'
    DATA_ACCESS_CAT = 'data_access'
    DATA_MODIFICATION = 'data_modification'
    SYSTEM = 'system'
    
    # Severities
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
    CRITICAL = 'critical'
    
    @staticmethod
    def log_event(event_type, description, user_id=None, username=None, user_role=None,
                  ip_address=None, user_agent=None, endpoint=None, method=None,
                  category=None, severity=INFO, success='success', details=None):
        """
        Log an audit event
        
        Args:
            event_type: Type of event (use class constants)
            description: Human-readable description
            user_id: User ID (if applicable)
            username: Username
            user_role: User role
            ip_address: Client IP
            user_agent: User agent string
            endpoint: API endpoint or route
            method: HTTP method
            category: Event category
            severity: Event severity (info, warning, error, critical)
            success: 'success', 'failure', or 'blocked'
            details: Additional details as dict (will be JSON encoded)
        """
        try:
            session = AuditSession()
            
            log_entry = AuditLog(
                event_type=event_type,
                event_category=category or AuditLogger._infer_category(event_type),
                severity=severity,
                user_id=user_id,
                username=username,
                user_role=user_role,
                ip_address=ip_address,
                user_agent=user_agent,
                endpoint=endpoint,
                method=method,
                description=description,
                details=json.dumps(details) if details else None,
                success=success
            )
            
            session.add(log_entry)
            session.commit()
            
        except Exception as e:
            print(f"❌ Audit logging error: {e}")
            # Don't let audit failures break the application
            try:
                session.rollback()
            except:
                pass
        finally:
            try:
                session.close()
            except:
                pass
    
    @staticmethod
    def _infer_category(event_type):
        """Infer category from event type"""
        if event_type in ['login_attempt', 'login_success', 'login_failure', 'logout', 'register', 'password_change']:
            return AuditLogger.AUTHENTICATION
        elif event_type in ['permission_denied', 'account_locked']:
            return AuditLogger.AUTHORIZATION
        elif event_type in ['data_access', 'file_download']:
            return AuditLogger.DATA_ACCESS_CAT
        elif event_type in ['data_create', 'data_update', 'data_delete']:
            return AuditLogger.DATA_MODIFICATION
        else:
            return AuditLogger.SYSTEM
    
    @staticmethod
    def log_from_request(event_type, description, current_user=None, success='success', 
                        severity=INFO, details=None):
        """
        Convenient method to log from Flask request context
        
        Args:
            event_type: Event type
            description: Description
            current_user: Flask-Login current_user object
            success: success/failure/blocked
            severity: Event severity
            details: Additional details dict
        """
        from flask import request
        
        # Get user info
        user_id = current_user.id if current_user and hasattr(current_user, 'id') and current_user.is_authenticated else None
        username = current_user.username if current_user and hasattr(current_user, 'username') and current_user.is_authenticated else None
        user_role = current_user.role.name if current_user and hasattr(current_user, 'role') and current_user.is_authenticated else None
        
        # Get request info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        user_agent = request.headers.get('User-Agent', '')[:255]
        endpoint = request.endpoint
        method = request.method
        
        AuditLogger.log_event(
            event_type=event_type,
            description=description,
            user_id=user_id,
            username=username,
            user_role=user_role,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            method=method,
            severity=severity,
            success=success,
            details=details
        )
    
    @staticmethod
    def get_logs(limit=100, event_type=None, username=None, ip_address=None, 
                 start_date=None, end_date=None, severity=None):
        """
        Query audit logs
        
        Returns:
            List of AuditLog objects
        """
        try:
            session = AuditSession()
            query = session.query(AuditLog)
            
            if event_type:
                query = query.filter(AuditLog.event_type == event_type)
            if username:
                query = query.filter(AuditLog.username == username)
            if ip_address:
                query = query.filter(AuditLog.ip_address == ip_address)
            if severity:
                query = query.filter(AuditLog.severity == severity)
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            return logs
            
        except Exception as e:
            print(f"❌ Error querying audit logs: {e}")
            return []
        finally:
            try:
                session.close()
            except:
                pass
    
    @staticmethod
    def get_failed_logins(username=None, hours=24):
        """
        Get failed login attempts in last N hours
        """
        from datetime import timedelta
        start_date = datetime.utcnow() - timedelta(hours=hours)
        
        return AuditLogger.get_logs(
            event_type=AuditLogger.LOGIN_FAILURE,
            username=username,
            start_date=start_date,
            limit=1000
        )


# Convenience function
def audit_log(event_type, description, **kwargs):
    """Quick audit logging function"""
    AuditLogger.log_from_request(event_type, description, **kwargs)
