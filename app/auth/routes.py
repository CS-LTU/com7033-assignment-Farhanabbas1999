from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.extensions import db, mongo, csrf
from app.models import User, Role

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    # If already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        print(f"User already authenticated: {current_user.username}, Role: {current_user.role.name if current_user.role else 'None'}")
        if hasattr(current_user, 'role') and current_user.role:
            if current_user.role.name == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif current_user.role.name == 'doctor':
                return redirect(url_for('doctor.dashboard'))
            elif current_user.role.name == 'nurse':
                return redirect(url_for('nurse.dashboard'))
            else:
                return redirect(url_for('patient.dashboard'))
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False)

        print(f"Login attempt - Username: {username}")

        user = User.query.filter_by(username=username).first()

        if not user:
            print(f"User not found: {username}")
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))
        
        print(f"User found - ID: {user.id}, Username: {user.username}, Role: {user.role.name if user.role else 'None'}")
        print(f"User active: {user.is_active}")
        
        # Check password
        password_valid = user.check_password(password)
        print(f"Password valid: {password_valid}")
        
        if not password_valid:
            print(f"Invalid password for user: {username}")
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        # Check if user is approved using SQL
        from sqlalchemy import text
        result = db.session.execute(text(f"SELECT is_approved FROM users WHERE id = {user.id}")).fetchone()
        is_approved = result[0] if result else False
        print(f"User approved (from DB): {is_approved}")
        
        if not is_approved:
            print(f"User not approved: {username}")
            flash('Your account is pending approval. Please wait for admin approval.', 'warning')
            return redirect(url_for('auth.login'))
        
        # Check if user is active
        if not user.is_active:
            print(f"User not active: {username}")
            flash('Your account has been deactivated. Please contact the administrator.', 'danger')
            return redirect(url_for('auth.login'))

        # Login successful
        print(f"Logging in user: {username}")
        login_user(user, remember=remember)
        print(f"Login successful. Current user authenticated: {current_user.is_authenticated}")
        
        # Redirect based on role
        if hasattr(user, 'role') and user.role:
            role_name = user.role.name
            print(f"Redirecting to {role_name} dashboard")
            
            if role_name == 'admin':
                flash(f'Welcome back, Admin {user.username}!', 'success')
                return redirect(url_for('admin.dashboard'))
            elif role_name == 'doctor':
                flash(f'Welcome back, Dr. {user.username}!', 'success')
                return redirect(url_for('doctor.dashboard'))
            elif role_name == 'nurse':
                flash(f'Welcome back, Nurse {user.username}!', 'success')
                return redirect(url_for('nurse.dashboard'))
            else:
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('patient.dashboard'))
        
        print("No role found, redirecting to main.index")
        return redirect(url_for('main.index'))

    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role', 'patient')

        # Prevent admin registration through public form
        if role_name == 'admin':
            flash('Invalid role selection. Admin accounts must be created by system administrators.', 'danger')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('auth.register'))

        role = Role.query.filter_by(name=role_name).first()
        if not role:
            flash('Invalid role', 'danger')
            return redirect(url_for('auth.register'))
        
        # Patients are auto-approved, doctors/nurses need approval
        is_approved = (role_name == 'patient')
        
        user = User(
            username=username, 
            email=email, 
            role_id=role.id,
            is_approved=is_approved,
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Create MongoDB patient record for patients
        if role_name == 'patient':
            try:
                mongo.db.patients.insert_one({
                    'user_id': user.id,
                    'name': username,
                    'email': email,
                    'medical_history': [],
                    'vitals': [],
                    'created_at': __import__('datetime').datetime.utcnow()
                })
            except Exception as e:
                print(f"Error creating patient record in MongoDB: {str(e)}")

        if is_approved:
            flash('Registration successful! Please log in.', 'success')
        else:
            flash('Registration successful! Your account is pending admin approval.', 'info')
        
        return redirect(url_for('auth.login'))
    
    roles = Role.query.filter(Role.name != 'admin').all()
    return render_template('auth/register.html', roles=roles)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('main.index'))