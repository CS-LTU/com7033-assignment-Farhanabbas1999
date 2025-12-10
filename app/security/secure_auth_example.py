"""
Enhanced Secure Authentication Routes
Demonstrates security best practices integration
This is a REFERENCE implementation - does not replace existing auth routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, Role
from app import db
from app.security import (
    InputValidator, sanitize_input, AuditLogger, 
    rate_limit, get_rate_limiter, get_client_ip
)
from datetime import datetime, timedelta

secure_auth_bp = Blueprint('secure_auth', __name__, url_prefix='/secure-auth')

@secure_auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=5, window_minutes=15, block_minutes=30)
def secure_login():
    """
    Enhanced secure login with:
    - Input validation and sanitization
    - Rate limiting
    - Audit logging
    - Session security
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        # Get and sanitize inputs
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')  # Never log passwords
        
        client_ip = get_client_ip()
        
        # Validate inputs
        is_valid_username, username_msg = InputValidator.validate_username(username)
        if not is_valid_username:
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Login failed: Invalid username format from {client_ip}",
                success='failure',
                severity=AuditLogger.WARNING,
                details={'reason': 'invalid_username_format', 'ip': client_ip}
            )
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('secure_auth.secure_login'))
        
        if not password or len(password) < 6 or len(password) > 128:
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Login failed: Invalid password format for {username}",
                success='failure',
                severity=AuditLogger.WARNING,
                details={'username': username, 'ip': client_ip, 'reason': 'invalid_password_format'}
            )
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('secure_auth.secure_login'))
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Login failed: User not found - {username}",
                success='failure',
                severity=AuditLogger.WARNING,
                details={'username': username, 'ip': client_ip, 'reason': 'user_not_found'}
            )
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('secure_auth.secure_login'))
        
        # Check if user is active
        if not user.is_active:
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Login failed: Inactive account - {username}",
                success='blocked',
                severity=AuditLogger.WARNING,
                details={'username': username, 'user_id': user.id, 'ip': client_ip, 'reason': 'account_inactive'}
            )
            flash('Your account has been deactivated. Please contact the administrator.', 'danger')
            return redirect(url_for('secure_auth.secure_login'))
        
        # Check password
        if not user.check_password(password):
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Login failed: Incorrect password for {username}",
                success='failure',
                severity=AuditLogger.WARNING,
                details={'username': username, 'user_id': user.id, 'ip': client_ip, 'reason': 'wrong_password'}
            )
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('secure_auth.secure_login'))
        
        # Login successful - reset rate limiter
        rate_limiter = get_rate_limiter()
        rate_limiter.reset_attempts(client_ip)
        
        # Set secure session
        session.permanent = True
        session['last_activity'] = datetime.utcnow().isoformat()
        
        login_user(user)
        
        # Log successful login
        AuditLogger.log_from_request(
            AuditLogger.LOGIN_SUCCESS,
            f"Successful login: {username} ({user.role.name})",
            current_user=user,
            success='success',
            severity=AuditLogger.INFO,
            details={'user_id': user.id, 'role': user.role.name, 'ip': client_ip}
        )
        
        flash(f'Welcome back, {user.full_name or user.username}!', 'success')
        
        # Redirect based on role
        if user.role.name == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif user.role.name == 'doctor':
            return redirect(url_for('doctor.dashboard'))
        elif user.role.name == 'nurse':
            return redirect(url_for('nurse.dashboard'))
        elif user.role.name == 'patient':
            return redirect(url_for('patient.dashboard'))
        
        return redirect(url_for('main.index'))
    
    return render_template('auth/login.html')


@secure_auth_bp.route('/register', methods=['GET', 'POST'])
def secure_register():
    """
    Enhanced secure registration with:
    - Strong password validation
    - Input sanitization
    - Audit logging
    """
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        # Get and sanitize inputs
        username = sanitize_input(request.form.get('username', '').strip())
        email = sanitize_input(request.form.get('email', '').strip().lower())
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = sanitize_input(request.form.get('full_name', '').strip())
        phone = sanitize_input(request.form.get('phone', '').strip())
        role_id = request.form.get('role_id')
        
        client_ip = get_client_ip()
        
        # Comprehensive validation
        errors = []
        
        # Username validation
        is_valid, msg = InputValidator.validate_username(username)
        if not is_valid:
            errors.append(msg)
        
        # Email validation
        is_valid, msg = InputValidator.validate_email(email)
        if not is_valid:
            errors.append(msg)
        
        # Password validation
        is_valid, msg = InputValidator.validate_password(password)
        if not is_valid:
            errors.append(msg)
        
        # Confirm password
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        # Full name validation
        is_valid, msg = InputValidator.validate_name(full_name, "Full name")
        if not is_valid:
            errors.append(msg)
        
        # Phone validation
        is_valid, msg = InputValidator.validate_phone(phone)
        if not is_valid:
            errors.append(msg)
        
        # Role validation
        if not role_id or not role_id.isdigit():
            errors.append("Please select a valid role")
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            
            AuditLogger.log_from_request(
                AuditLogger.REGISTER,
                f"Registration failed: Validation errors for {username}",
                success='failure',
                severity=AuditLogger.INFO,
                details={'username': username, 'errors': errors, 'ip': client_ip}
            )
            return redirect(url_for('secure_auth.secure_register'))
        
        # Check for existing user
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            AuditLogger.log_from_request(
                AuditLogger.REGISTER,
                f"Registration failed: Username exists - {username}",
                success='failure',
                severity=AuditLogger.INFO,
                details={'username': username, 'reason': 'username_exists', 'ip': client_ip}
            )
            return redirect(url_for('secure_auth.secure_register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            AuditLogger.log_from_request(
                AuditLogger.REGISTER,
                f"Registration failed: Email exists - {email}",
                success='failure',
                severity=AuditLogger.INFO,
                details={'email': email, 'reason': 'email_exists', 'ip': client_ip}
            )
            return redirect(url_for('secure_auth.secure_register'))
        
        # Create new user
        try:
            new_user = User(
                username=username,
                email=email,
                full_name=full_name,
                phone=phone,
                role_id=int(role_id),
                is_active=True
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            AuditLogger.log_from_request(
                AuditLogger.REGISTER,
                f"User registered successfully: {username}",
                success='success',
                severity=AuditLogger.INFO,
                details={'user_id': new_user.id, 'username': username, 'role_id': role_id, 'ip': client_ip}
            )
            
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('secure_auth.secure_login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')
            
            AuditLogger.log_from_request(
                AuditLogger.REGISTER,
                f"Registration failed: Database error for {username}",
                success='failure',
                severity=AuditLogger.ERROR,
                details={'username': username, 'error': str(e), 'ip': client_ip}
            )
            return redirect(url_for('secure_auth.secure_register'))
    
    roles = Role.query.all()
    return render_template('auth/register.html', roles=roles)


@secure_auth_bp.route('/logout')
@login_required
def secure_logout():
    """
    Enhanced secure logout with audit logging
    """
    username = current_user.username
    user_id = current_user.id
    
    AuditLogger.log_from_request(
        AuditLogger.LOGOUT,
        f"User logged out: {username}",
        current_user=current_user,
        success='success',
        severity=AuditLogger.INFO,
        details={'user_id': user_id, 'username': username}
    )
    
    logout_user()
    session.clear()
    
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))


@secure_auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def secure_change_password():
    """
    Enhanced secure password change with validation and logging
    """
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate current password
        if not current_user.check_password(current_password):
            flash('Current password is incorrect!', 'danger')
            AuditLogger.log_from_request(
                AuditLogger.PASSWORD_CHANGE,
                f"Password change failed: Wrong current password for {current_user.username}",
                current_user=current_user,
                success='failure',
                severity=AuditLogger.WARNING
            )
            return redirect(url_for('secure_auth.secure_change_password'))
        
        # Validate new password
        is_valid, msg = InputValidator.validate_password(new_password)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('secure_auth.secure_change_password'))
        
        # Confirm password match
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return redirect(url_for('secure_auth.secure_change_password'))
        
        # Check if new password is different from current
        if current_user.check_password(new_password):
            flash('New password must be different from current password!', 'danger')
            return redirect(url_for('secure_auth.secure_change_password'))
        
        # Update password
        try:
            current_user.set_password(new_password)
            db.session.commit()
            
            AuditLogger.log_from_request(
                AuditLogger.PASSWORD_CHANGE,
                f"Password changed successfully for {current_user.username}",
                current_user=current_user,
                success='success',
                severity=AuditLogger.INFO
            )
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('main.index'))
            
        except Exception as e:
            db.session.rollback()
            flash('Failed to change password. Please try again.', 'danger')
            
            AuditLogger.log_from_request(
                AuditLogger.PASSWORD_CHANGE,
                f"Password change failed: Database error for {current_user.username}",
                current_user=current_user,
                success='failure',
                severity=AuditLogger.ERROR,
                details={'error': str(e)}
            )
    
    return render_template('profile/change_password.html')
