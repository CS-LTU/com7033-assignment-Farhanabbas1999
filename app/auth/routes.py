from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User, Role
from app import db

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect based on role
        if current_user.role.name == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif current_user.role.name == 'doctor':
            return redirect(url_for('doctor.dashboard'))
        elif current_user.role.name == 'nurse':
            return redirect(url_for('nurse.dashboard'))
        elif current_user.role.name == 'patient':
            return redirect(url_for('patient.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('auth.login'))
        
        # Check if user is active
        if not user.is_active:
            flash('Your account has been deactivated. Please contact the administrator.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Check password
        if not user.check_password(password):
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('auth.login'))
        
        # Login successful
        login_user(user)
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

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        
        # Validation
        if not all([username, email, password, confirm_password, full_name, role_id]):
            flash('Please fill in all required fields!', 'danger')
            return redirect(url_for('auth.register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('auth.register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('auth.register'))
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('auth.register'))
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('auth.register'))
        
        # Create new user
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
        
        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('auth.login'))
    
    # Get all roles for dropdown
    roles = Role.query.all()
    return render_template('auth/register.html', roles=roles)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('main.index'))

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([current_password, new_password, confirm_password]):
            flash('Please fill in all fields!', 'danger')
            return redirect(url_for('auth.change_password'))
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect!', 'danger')
            return redirect(url_for('auth.change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger')
            return redirect(url_for('auth.change_password'))
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('auth.change_password'))
        
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        
        # Redirect based on role
        if current_user.role.name == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif current_user.role.name == 'doctor':
            return redirect(url_for('doctor.dashboard'))
        elif current_user.role.name == 'nurse':
            return redirect(url_for('nurse.dashboard'))
        elif current_user.role.name == 'patient':
            return redirect(url_for('patient.dashboard'))
    
    return render_template('auth/change_password.html')