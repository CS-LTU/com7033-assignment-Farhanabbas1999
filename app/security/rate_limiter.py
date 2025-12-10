"""
Rate Limiting Module
Prevents brute force attacks and DDoS
"""
from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import time

class RateLimiter:
    """
    In-memory rate limiter for login attempts and API calls
    """
    
    def __init__(self):
        # Store: {identifier: [(timestamp1, count1), (timestamp2, count2), ...]}
        self.attempts = {}
        self.blocked_ips = {}  # {ip: block_until_timestamp}
    
    def is_blocked(self, identifier):
        """
        Check if identifier is currently blocked
        """
        if identifier in self.blocked_ips:
            block_until = self.blocked_ips[identifier]
            if datetime.now() < block_until:
                return True, block_until
            else:
                # Unblock expired entries
                del self.blocked_ips[identifier]
        return False, None
    
    def record_attempt(self, identifier, max_attempts=5, window_minutes=15, block_minutes=30):
        """
        Record an attempt and check if limit exceeded
        
        Args:
            identifier: IP address or username
            max_attempts: Maximum attempts allowed in window
            window_minutes: Time window for counting attempts
            block_minutes: How long to block after exceeding limit
        
        Returns:
            (is_allowed, remaining_attempts, reset_time)
        """
        now = datetime.now()
        window_start = now - timedelta(minutes=window_minutes)
        
        # Check if blocked
        is_blocked, block_until = self.is_blocked(identifier)
        if is_blocked:
            wait_seconds = int((block_until - now).total_seconds())
            return False, 0, wait_seconds
        
        # Clean old attempts
        if identifier in self.attempts:
            self.attempts[identifier] = [
                (ts, cnt) for ts, cnt in self.attempts[identifier]
                if ts > window_start
            ]
        else:
            self.attempts[identifier] = []
        
        # Add current attempt
        self.attempts[identifier].append((now, 1))
        
        # Count total attempts in window
        total_attempts = sum(cnt for ts, cnt in self.attempts[identifier])
        
        if total_attempts > max_attempts:
            # Block the identifier
            self.blocked_ips[identifier] = now + timedelta(minutes=block_minutes)
            return False, 0, block_minutes * 60
        
        remaining = max_attempts - total_attempts
        return True, remaining, window_minutes * 60
    
    def reset_attempts(self, identifier):
        """
        Reset attempts for identifier (e.g., after successful login)
        """
        if identifier in self.attempts:
            del self.attempts[identifier]
        if identifier in self.blocked_ips:
            del self.blocked_ips[identifier]
    
    def cleanup_old_entries(self, hours=24):
        """
        Clean up old entries to prevent memory bloat
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        
        # Clean attempts
        for identifier in list(self.attempts.keys()):
            self.attempts[identifier] = [
                (ts, cnt) for ts, cnt in self.attempts[identifier]
                if ts > cutoff
            ]
            if not self.attempts[identifier]:
                del self.attempts[identifier]
        
        # Clean expired blocks
        now = datetime.now()
        for ip in list(self.blocked_ips.keys()):
            if self.blocked_ips[ip] < now:
                del self.blocked_ips[ip]


# Global rate limiter instance
_rate_limiter = RateLimiter()

def get_rate_limiter():
    """Get singleton rate limiter instance"""
    return _rate_limiter


def rate_limit(max_attempts=5, window_minutes=15, block_minutes=30, by_ip=True):
    """
    Decorator for rate limiting routes
    
    Args:
        max_attempts: Maximum attempts in window
        window_minutes: Time window in minutes
        block_minutes: Block duration in minutes
        by_ip: If True, limit by IP. If False, limit by username from form
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            limiter = get_rate_limiter()
            
            if by_ip:
                identifier = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                                request.environ.get('REMOTE_ADDR', 'unknown'))
            else:
                identifier = request.form.get('username', 'unknown')
            
            is_allowed, remaining, wait_time = limiter.record_attempt(
                identifier, max_attempts, window_minutes, block_minutes
            )
            
            if not is_allowed:
                if request.is_json:
                    return jsonify({
                        'error': 'Too many attempts',
                        'wait_seconds': wait_time,
                        'message': f'Please wait {wait_time // 60} minutes before trying again'
                    }), 429
                else:
                    from flask import flash, redirect, url_for
                    flash(f'Too many attempts. Please wait {wait_time // 60} minutes.', 'danger')
                    return redirect(url_for('auth.login'))
            
            return f(*args, **kwargs)
        return wrapped
    return decorator
