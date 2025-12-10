"""
Input Validation and Sanitization Module
Prevents XSS, SQL Injection, and other injection attacks
"""
import re
import bleach
from flask import request
from markupsafe import escape

class InputValidator:
    """Comprehensive input validation for security"""
    
    @staticmethod
    def validate_username(username):
        """
        Validate username: alphanumeric, underscore, 3-30 chars
        """
        if not username or len(username) < 3 or len(username) > 30:
            return False, "Username must be 3-30 characters"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        return True, "Valid"
    
    @staticmethod
    def validate_email(email):
        """
        Validate email format
        """
        if not email:
            return False, "Email is required"
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        if len(email) > 120:
            return False, "Email is too long"
        
        return True, "Valid"
    
    @staticmethod
    def validate_password(password):
        """
        Strong password validation:
        - At least 8 characters
        - Contains uppercase letter
        - Contains lowercase letter
        - Contains number
        - Contains special character
        """
        if not password:
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if len(password) > 128:
            return False, "Password is too long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Valid"
    
    @staticmethod
    def validate_phone(phone):
        """
        Validate phone number format
        """
        if not phone:
            return True, "Valid"  # Phone is optional
        
        # Allow digits, spaces, +, -, ()
        phone_pattern = r'^[\d\s\+\-\(\)]+$'
        if not re.match(phone_pattern, phone):
            return False, "Invalid phone number format"
        
        if len(phone) > 20:
            return False, "Phone number is too long"
        
        return True, "Valid"
    
    @staticmethod
    def validate_name(name, field_name="Name"):
        """
        Validate name fields (full name, etc.)
        """
        if not name:
            return False, f"{field_name} is required"
        
        if len(name) < 2 or len(name) > 120:
            return False, f"{field_name} must be 2-120 characters"
        
        # Allow letters, spaces, hyphens, apostrophes
        if not re.match(r"^[a-zA-Z\s\-']+$", name):
            return False, f"{field_name} contains invalid characters"
        
        return True, "Valid"
    
    @staticmethod
    def validate_numeric(value, min_val=None, max_val=None, field_name="Value"):
        """
        Validate numeric input
        """
        try:
            num = float(value)
            
            if min_val is not None and num < min_val:
                return False, f"{field_name} must be at least {min_val}"
            
            if max_val is not None and num > max_val:
                return False, f"{field_name} must be at most {max_val}"
            
            return True, "Valid"
        except (ValueError, TypeError):
            return False, f"{field_name} must be a number"
    
    @staticmethod
    def validate_date(date_str):
        """
        Validate date format (YYYY-MM-DD)
        """
        if not date_str:
            return False, "Date is required"
        
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', date_str):
            return False, "Date must be in YYYY-MM-DD format"
        
        return True, "Valid"
    
    @staticmethod
    def validate_time(time_str):
        """
        Validate time format (HH:MM)
        """
        if not time_str:
            return False, "Time is required"
        
        if not re.match(r'^\d{2}:\d{2}$', time_str):
            return False, "Time must be in HH:MM format"
        
        return True, "Valid"
    
    @staticmethod
    def validate_text_length(text, min_len=0, max_len=1000, field_name="Text"):
        """
        Validate text field length
        """
        if not text and min_len > 0:
            return False, f"{field_name} is required"
        
        if text and len(text) < min_len:
            return False, f"{field_name} must be at least {min_len} characters"
        
        if text and len(text) > max_len:
            return False, f"{field_name} must be at most {max_len} characters"
        
        return True, "Valid"


def sanitize_input(text, allow_html=False):
    """
    Sanitize user input to prevent XSS attacks
    
    Args:
        text: Input text to sanitize
        allow_html: If True, allow safe HTML tags (for rich text)
    
    Returns:
        Sanitized text
    """
    if not text:
        return text
    
    if allow_html:
        # Allow only safe HTML tags
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li']
        allowed_attrs = {'a': ['href', 'title']}
        return bleach.clean(text, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    else:
        # Escape all HTML
        return escape(text)


def sanitize_filename(filename):
    """
    Sanitize filename for secure file uploads
    """
    if not filename:
        return None
    
    # Remove path components
    filename = filename.split('/')[-1].split('\\')[-1]
    
    # Allow only alphanumeric, dash, underscore, and dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + ('.' + ext if ext else '')
    
    return filename


def validate_file_upload(file, allowed_extensions=None, max_size_mb=16):
    """
    Validate file upload
    
    Args:
        file: FileStorage object from request.files
        allowed_extensions: Set of allowed file extensions (e.g., {'jpg', 'png', 'pdf'})
        max_size_mb: Maximum file size in MB
    
    Returns:
        (is_valid, error_message)
    """
    if not file or file.filename == '':
        return False, "No file selected"
    
    # Check filename
    if not file.filename:
        return False, "Invalid filename"
    
    # Check extension
    if allowed_extensions:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in allowed_extensions:
            return False, f"File type not allowed. Allowed: {', '.join(allowed_extensions)}"
    
    # Check file size (approximation from content length header)
    if hasattr(file, 'content_length') and file.content_length:
        max_size = max_size_mb * 1024 * 1024
        if file.content_length > max_size:
            return False, f"File too large. Maximum size: {max_size_mb}MB"
    
    return True, "Valid"


def get_client_ip():
    """
    Get real client IP address (considering proxies)
    """
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        # Behind proxy
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')
