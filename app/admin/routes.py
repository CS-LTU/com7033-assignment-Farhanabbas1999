from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role
from app import db, mongo
from datetime import datetime
from bson import ObjectId
import pandas as pd
import json
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'admin':
            flash('You need to be an administrator to access this page!', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with statistics"""
    stats = {
        'total_users': User.query.count(),
        'total_doctors': User.query.join(Role).filter(Role.name == 'doctor').count(),
        'total_nurses': User.query.join(Role).filter(Role.name == 'nurse').count(),
        'total_patients': User.query.join(Role).filter(Role.name == 'patient').count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'pending_approvals': User.query.filter_by(is_approved=False).count(),
        'total_appointments': 0,
        'pending_appointments': 0,
        'total_predictions': 0
    }
    
    # Get MongoDB stats
    if mongo.db is not None:
        try:
            stats['total_appointments'] = mongo.db.appointments.count_documents({})
            stats['pending_appointments'] = mongo.db.appointments.count_documents({'status': 'pending'})
            stats['total_predictions'] = mongo.db.predictions.count_documents({})
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_users=recent_users)

@admin_bp.route('/users')
@login_required
@admin_required
def manage_users():
    """Manage all users"""
    users = User.query.order_by(User.created_at.desc()).all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)

@admin_bp.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Create a new user"""
    try:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            phone=phone,
            role_id=role_id,
            is_active=True,
            is_approved=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('admin.manage_users'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating user: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit user details"""
    user = User.query.get_or_404(user_id)
    
    user.username = request.form.get('username')
    user.email = request.form.get('email')
    user.full_name = request.form.get('full_name')
    user.phone = request.form.get('phone')
    user.role_id = int(request.form.get('role_id'))
    
    # Update password if provided
    new_password = request.form.get('password')
    if new_password:
        user.set_password(new_password)
    
    db.session.commit()
    flash(f'User {user.username} updated successfully!', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Activate or deactivate user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deactivating yourself
    if user.id == current_user.id:
        flash('You cannot deactivate your own account!', 'danger')
        return redirect(url_for('admin.manage_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}!', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    """Approve pending user"""
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    
    flash(f'User {user.username} has been approved!', 'success')
    return redirect(url_for('admin.pending_approvals'))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin.manage_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been deleted!', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/doctors')
@login_required
@admin_required
def manage_doctors():
    """Manage doctors"""
    doctor_role = Role.query.filter_by(name='doctor').first()
    doctors = User.query.filter_by(role_id=doctor_role.id).all() if doctor_role else []
    return render_template('admin/doctors.html', doctors=doctors)

@admin_bp.route('/nurses')
@login_required
@admin_required
def manage_nurses():
    """Manage nurses"""
    nurse_role = Role.query.filter_by(name='nurse').first()
    nurses = User.query.filter_by(role_id=nurse_role.id).all() if nurse_role else []
    return render_template('admin/nurses.html', nurses=nurses)

@admin_bp.route('/patients')
@login_required
@admin_required
def manage_patients():
    """Manage patients"""
    patient_role = Role.query.filter_by(name='patient').first()
    patients = User.query.filter_by(role_id=patient_role.id).all() if patient_role else []
    
    # Get statistics
    stats = {
        'total_patients': len(patients),
        'active_patients': len([p for p in patients if p.is_active]),
        'pending_approvals': len([p for p in patients if not p.is_approved]),
        'total_records': 0
    }
    
    # Get patient data from MongoDB
    patient_data = {}
    if mongo.db is not None:
        try:
            for patient in patients:
                data = mongo.db.patients.find_one({'user_id': patient.id})
                if data:
                    patient_data[patient.id] = data
            
            stats['total_records'] = mongo.db.patients.count_documents({})
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('admin/patients.html', patients=patients, patient_data=patient_data, stats=stats)

@admin_bp.route('/pending-approvals')
@login_required
@admin_required
def pending_approvals():
    """View pending user approvals"""
    pending_users = User.query.filter_by(is_approved=False).order_by(User.created_at.desc()).all()
    return render_template('admin/pending_approvals.html', pending_users=pending_users)

@admin_bp.route('/appointments')
@login_required
@admin_required
def view_appointments():
    """View all appointments"""
    appointments = []
    
    if mongo.db is not None:
        try:
            apts = list(mongo.db.appointments.find().sort('date', -1))
            
            for apt in apts:
                patient = User.query.get(apt.get('patient_id'))
                doctor = User.query.get(apt.get('doctor_id'))
                apt['patient'] = patient
                apt['doctor'] = doctor
                apt['_id'] = str(apt['_id'])
                appointments.append(apt)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('admin/appointments.html', appointments=appointments)

@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """Generate system reports"""
    stats = {
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'inactive_users': User.query.filter_by(is_active=False).count(),
        'total_doctors': User.query.join(Role).filter(Role.name == 'doctor').count(),
        'total_nurses': User.query.join(Role).filter(Role.name == 'nurse').count(),
        'total_patients': User.query.join(Role).filter(Role.name == 'patient').count(),
    }
    
    if mongo.db is not None:
        try:
            stats['total_appointments'] = mongo.db.appointments.count_documents({})
            stats['pending_appointments'] = mongo.db.appointments.count_documents({'status': 'pending'})
            stats['accepted_appointments'] = mongo.db.appointments.count_documents({'status': 'accepted'})
            stats['rejected_appointments'] = mongo.db.appointments.count_documents({'status': 'rejected'})
            stats['total_predictions'] = mongo.db.predictions.count_documents({})
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('admin/reports.html', stats=stats)

@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """View system analytics from CSV data"""
    try:
        # Path to CSV file
        csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'healthcare-dataset-stroke-data.csv')
        
        # Read CSV
        df = pd.read_csv(csv_path)
        
        # Calculate analytics
        stroke_analytics = calculate_stroke_analytics(df)
        
        # Convert to JSON for JavaScript
        stroke_analytics_json = json.dumps(stroke_analytics)
        
        # Get general stats
        stats = {
            'total_users': User.query.count(),
            'total_predictions': 0
        }
        
        if mongo.db is not None:
            try:
                stats['total_predictions'] = mongo.db.predictions.count_documents({})
            except:
                pass
        
        return render_template('admin/analytics.html', 
                             stroke_analytics=stroke_analytics,
                             stroke_analytics_json=stroke_analytics_json,
                             stats=stats)
    except Exception as e:
        flash(f'Error loading analytics: {str(e)}', 'danger')
        return redirect(url_for('admin.dashboard'))

def calculate_stroke_analytics(df):
    """Calculate analytics from dataframe"""
    
    # Total records
    total_records = len(df)
    
    # Stroke distribution
    stroke_distribution = {
        'stroke': int(df[df['stroke'] == 1].shape[0]),
        'no_stroke': int(df[df['stroke'] == 0].shape[0])
    }
    
    # Age groups vs Stroke
    age_bins = [0, 18, 30, 45, 60, 75, 100]
    age_labels = ['0-18', '19-30', '31-45', '46-60', '61-75', '76+']
    df['age_group'] = pd.cut(df['age'], bins=age_bins, labels=age_labels, include_lowest=True)
    
    age_vs_stroke = df[df['stroke'] == 1].groupby('age_group').size().to_dict()
    age_vs_stroke = {str(k): int(v) for k, v in age_vs_stroke.items()}
    
    # Gender vs Stroke
    gender_vs_stroke = df[df['stroke'] == 1].groupby('gender').size().to_dict()
    gender_vs_stroke = {str(k): int(v) for k, v in gender_vs_stroke.items()}
    
    # Hypertension vs Stroke
    hypertension_vs_stroke = {
        'with_hypertension_stroke': int(df[(df['hypertension'] == 1) & (df['stroke'] == 1)].shape[0]),
        'without_hypertension_stroke': int(df[(df['hypertension'] == 0) & (df['stroke'] == 1)].shape[0]),
        'with_hypertension_total': int(df[df['hypertension'] == 1].shape[0]),
        'without_hypertension_total': int(df[df['hypertension'] == 0].shape[0])
    }
    
    # Heart Disease vs Stroke
    heart_disease_vs_stroke = {
        'with_heart_disease_stroke': int(df[(df['heart_disease'] == 1) & (df['stroke'] == 1)].shape[0]),
        'without_heart_disease_stroke': int(df[(df['heart_disease'] == 0) & (df['stroke'] == 1)].shape[0]),
        'with_heart_disease_total': int(df[df['heart_disease'] == 1].shape[0]),
        'without_heart_disease_total': int(df[df['heart_disease'] == 0].shape[0])
    }
    
    # Smoking vs Stroke
    smoking_vs_stroke = df[df['stroke'] == 1].groupby('smoking_status').size().to_dict()
    smoking_vs_stroke = {str(k): int(v) for k, v in smoking_vs_stroke.items()}
    
    # BMI categories vs Stroke
    bmi_bins = [0, 18.5, 25, 30, 100]
    bmi_labels = ['Underweight', 'Normal', 'Overweight', 'Obese']
    df['bmi_category'] = pd.cut(df['bmi'], bins=bmi_bins, labels=bmi_labels, include_lowest=True)
    
    bmi_vs_stroke = df[df['stroke'] == 1].groupby('bmi_category').size().to_dict()
    bmi_vs_stroke = {str(k): int(v) for k, v in bmi_vs_stroke.items()}
    
    # Glucose levels
    glucose_vs_stroke = {
        'stroke_avg': float(df[df['stroke'] == 1]['avg_glucose_level'].mean()),
        'no_stroke_avg': float(df[df['stroke'] == 0]['avg_glucose_level'].mean())
    }
    
    # Glucose categories
    glucose_bins = [0, 100, 125, 200, 300]
    glucose_labels = ['Normal', 'Prediabetic', 'Diabetic', 'High']
    df['glucose_category'] = pd.cut(df['avg_glucose_level'], bins=glucose_bins, labels=glucose_labels, include_lowest=True)
    
    glucose_cat_stroke = df[df['stroke'] == 1].groupby('glucose_category').size().to_dict()
    glucose_cat_stroke = {str(k): int(v) for k, v in glucose_cat_stroke.items()}
    
    return {
        'total_records': total_records,
        'stroke_distribution': stroke_distribution,
        'age_vs_stroke': {
            'labels': list(age_vs_stroke.keys()),
            'data': list(age_vs_stroke.values())
        },
        'gender_vs_stroke': gender_vs_stroke,
        'hypertension_vs_stroke': hypertension_vs_stroke,
        'heart_disease_vs_stroke': heart_disease_vs_stroke,
        'smoking_vs_stroke': smoking_vs_stroke,
        'bmi_vs_stroke': bmi_vs_stroke,
        'glucose_vs_stroke': glucose_vs_stroke,
        'glucose_categories_vs_stroke': {
            'labels': list(glucose_cat_stroke.keys()),
            'data': list(glucose_cat_stroke.values())
        }
    }