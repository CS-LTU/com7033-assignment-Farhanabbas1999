from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

def admin_required(f):
    """
    Decorator to require admin role for access to a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not hasattr(current_user, 'role') or current_user.role.name != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def doctor_required(f):
    """
    Decorator to require doctor role for access to a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not hasattr(current_user, 'role') or current_user.role.name != 'doctor':
            flash('Access denied. Doctor privileges required.', 'danger')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def nurse_required(f):
    """
    Decorator to require nurse role for access to a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not hasattr(current_user, 'role') or current_user.role.name != 'nurse':
            flash('Access denied. Nurse privileges required.', 'danger')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def patient_required(f):
    """
    Decorator to require patient role for access to a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        if not hasattr(current_user, 'role') or current_user.role.name != 'patient':
            flash('Access denied. Patient privileges required.', 'danger')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """
    Decorator to require one of multiple roles for access to a route.
    Usage: @role_required('admin', 'doctor')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            
            if not hasattr(current_user, 'role') or current_user.role.name not in roles:
                flash(f'Access denied. Required role: {" or ".join(roles)}', 'danger')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator