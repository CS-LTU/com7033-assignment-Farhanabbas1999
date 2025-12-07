from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.extensions import db, mongo
from app.models import User, Role
from app.admin.analytics import get_stroke_analytics
from werkzeug.security import generate_password_hash
import json

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role.name != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))
    
    total_users = User.query.count()
    total_doctors = User.query.join(Role).filter(Role.name == 'doctor').count()
    total_patients = User.query.join(Role).filter(Role.name == 'patient').count()
    total_nurses = User.query.join(Role).filter(Role.name == 'nurse').count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    # Get stroke analytics
    analytics = get_stroke_analytics()
    
    stats = {
        'total_users': total_users,
        'total_doctors': total_doctors,
        'total_patients': total_patients,
        'total_nurses': total_nurses,
        'active_users': User.query.filter_by(is_active=True).count(),
        'stroke_cases': analytics.get('stroke_cases', 0),
        'total_dataset_records': analytics.get('total_records', 0)
    }
    
    # Convert stats for Chart.js
    gender_data = analytics.get('gender_stats', {})
    age_data = analytics.get('age_stats', {})
    bmi_data = analytics.get('bmi_stats', {})
    
    return render_template('admin/dashboard.html', 
                         stats=stats, 
                         recent_users=recent_users,
                         gender_data=json.dumps(gender_data),
                         age_data=json.dumps(age_data),
                         bmi_data=json.dumps(bmi_data))

@admin_bp.route('/users')
@login_required
def users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/user/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin.create_user'))
        
        role = Role.query.filter_by(name=role_name).first()
        user = User(username=username, email=email, role_id=role.id)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        if role_name == 'patient':
            mongo.db.patients.insert_one({
                'user_id': user.id,
                'name': username,
                'email': email,
                'medical_history': [],
                'vitals': [],
                'created_at': __import__('datetime').datetime.utcnow()
            })
        
        flash('User created successfully', 'success')
        return redirect(url_for('admin.users'))
    
    roles = Role.query.all()
    return render_template('admin/create_user.html', roles=roles)

@admin_bp.route('/user/<user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('admin.users'))
    
    db.session.delete(user)
    db.session.commit()
    mongo.db.patients.delete_one({'user_id': int(user_id)})
    
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        role_name = request.form.get('role')
        user.role = Role.query.filter_by(name=role_name).first()
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin.users'))
    return render_template('admin/edit_user.html', user=user, roles=roles)

@admin_bp.route('/analytics')
@login_required
def analytics():
    analytics = get_stroke_analytics()
    return render_template('admin/analytics.html', analytics=analytics)

@admin_bp.route('/patients')
@login_required
def patients():
    patients = list(mongo.db.patients.find())
    return render_template('admin/patients.html', patients=patients)

@admin_bp.route('/reports')
@login_required
def reports():
    return render_template('admin/reports.html')

@admin_bp.route('/settings')
@login_required
def settings():
    return render_template('admin/settings.html')