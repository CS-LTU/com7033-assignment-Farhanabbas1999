from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role, Appointment, Prediction
from app import db
from sqlalchemy import desc
import pandas as pd
import os

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'admin':
            flash('You need to be an admin to access this page!', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard"""
    try:
        # Get statistics
        stats = {
            'total_users': User.query.count(),
            'total_doctors': User.query.join(Role).filter(Role.name == 'doctor').count(),
            'total_nurses': User.query.join(Role).filter(Role.name == 'nurse').count(),
            'total_patients': User.query.join(Role).filter(Role.name == 'patient').count(),
            'total_appointments': Appointment.query.count(),
            'pending_appointments': Appointment.query.filter_by(status='pending').count(),
            'total_predictions': Prediction.query.count(),
            'high_risk_predictions': Prediction.query.filter_by(prediction=1).count()
        }
        
        # Get recent users
        recent_users = User.query.order_by(desc(User.created_at)).limit(5).all()
        
        # Get recent appointments
        recent_appointments = Appointment.query.order_by(desc(Appointment.created_at)).limit(5).all()
        
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        stats = {
            'total_users': 0,
            'total_doctors': 0,
            'total_nurses': 0,
            'total_patients': 0,
            'total_appointments': 0,
            'pending_appointments': 0,
            'total_predictions': 0,
            'high_risk_predictions': 0
        }
        recent_users = []
        recent_appointments = []
    
    return render_template('admin/dashboard.html', 
                         stats=stats,
                         recent_users=recent_users,
                         recent_appointments=recent_appointments)

@admin_bp.route('/users')
@login_required
@admin_required
def manage_users():
    """Manage all users"""
    users = User.query.order_by(User.created_at.desc()).all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            flash('You cannot deactivate your own account!', 'danger')
        else:
            user.is_active = not user.is_active
            db.session.commit()
            status = 'activated' if user.is_active else 'deactivated'
            flash(f'User {user.username} has been {status}!', 'success')
    except Exception as e:
        print(f"Error toggling user status: {e}")
        db.session.rollback()
        flash('Error updating user status!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            flash('You cannot delete your own account!', 'danger')
        else:
            username = user.username
            db.session.delete(user)
            db.session.commit()
            flash(f'User {username} has been deleted!', 'success')
    except Exception as e:
        print(f"Error deleting user: {e}")
        db.session.rollback()
        flash('Error deleting user!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/change-role', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    """Change user role"""
    try:
        user = User.query.get_or_404(user_id)
        new_role_id = request.form.get('role_id')
        
        if user.id == current_user.id:
            flash('You cannot change your own role!', 'danger')
        else:
            role = Role.query.get(new_role_id)
            if role:
                user.role_id = new_role_id
                db.session.commit()
                flash(f'User {user.username} role changed to {role.name}!', 'success')
            else:
                flash('Invalid role selected!', 'danger')
    except Exception as e:
        print(f"Error changing user role: {e}")
        db.session.rollback()
        flash('Error changing user role!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/appointments')
@login_required
@admin_required
def view_appointments():
    """View all appointments"""
    appointments = Appointment.query.order_by(desc(Appointment.date)).all()
    
    stats = {
        'total': len(appointments),
        'pending': len([a for a in appointments if a.status == 'pending']),
        'confirmed': len([a for a in appointments if a.status == 'confirmed']),
        'cancelled': len([a for a in appointments if a.status == 'cancelled']),
        'completed': len([a for a in appointments if a.status == 'completed'])
    }
    
    return render_template('admin/appointments.html', appointments=appointments, stats=stats)

@admin_bp.route('/predictions')
@login_required
@admin_required
def view_predictions():
    """View all predictions"""
    predictions = Prediction.query.order_by(desc(Prediction.created_at)).all()
    
    stats = {
        'total': len(predictions),
        'high_risk': len([p for p in predictions if p.prediction == 1]),
        'low_risk': len([p for p in predictions if p.prediction == 0])
    }
    
    return render_template('admin/patient_records.html', predictions=predictions, stats=stats)

@admin_bp.route('/patients/<int:patient_id>/record')
@login_required
@admin_required
def view_patient_record(patient_id):
    """View detailed patient record"""
    try:
        # Get patient user
        patient = User.query.get_or_404(patient_id)
        
        # Get patient's predictions
        predictions = Prediction.query.filter_by(user_id=patient_id).order_by(desc(Prediction.created_at)).all()
        
        # Get patient's appointments
        appointments = Appointment.query.filter_by(patient_id=patient_id).order_by(desc(Appointment.date)).all()
        
        return render_template('admin/view_patient_record.html', 
                             patient=patient, 
                             predictions=predictions,
                             appointments=appointments)
    except Exception as e:
        print(f"Error viewing patient record: {e}")
        flash('Error loading patient record!', 'danger')
        return redirect(url_for('admin.view_predictions'))

@admin_bp.route('/users/<int:user_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_user(user_id):
    """Approve a user"""
    try:
        user = User.query.get_or_404(user_id)
        user.is_active = True
        db.session.commit()
        flash(f'User {user.username} has been approved!', 'success')
    except Exception as e:
        print(f"Error approving user: {e}")
        db.session.rollback()
        flash('Error approving user!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_user(user_id):
    """Reject and delete a user"""
    try:
        user = User.query.get_or_404(user_id)
        username = user.username
        
        if user.id == current_user.id:
            flash('You cannot reject your own account!', 'danger')
        else:
            db.session.delete(user)
            db.session.commit()
            flash(f'User {username} has been rejected and deleted!', 'success')
    except Exception as e:
        print(f"Error rejecting user: {e}")
        db.session.rollback()
        flash('Error rejecting user!', 'danger')
    
    return redirect(url_for('admin.pending_approvals'))

@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit a user"""
    try:
        user = User.query.get_or_404(user_id)
        
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        user.full_name = request.form.get('full_name', user.full_name)
        user.phone = request.form.get('phone', user.phone)
        
        role_id = request.form.get('role_id')
        if role_id:
            user.role_id = int(role_id)
        
        # Update password if provided
        new_password = request.form.get('password')
        if new_password and len(new_password) >= 6:
            user.set_password(new_password)
        
        db.session.commit()
        flash(f'User {user.username} has been updated!', 'success')
    except Exception as e:
        print(f"Error editing user: {e}")
        db.session.rollback()
        flash('Error updating user!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

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
        
        # Validation
        if not all([username, email, password, role_id]):
            flash('Please fill in all required fields!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
        # Check if email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('admin.manage_users'))
        
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
        
        flash(f'User {username} has been created successfully!', 'success')
    except Exception as e:
        print(f"Error creating user: {e}")
        db.session.rollback()
        flash('Error creating user!', 'danger')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/doctors')
@login_required
@admin_required
def manage_doctors():
    """Manage doctors"""
    doctor_role = Role.query.filter_by(name='doctor').first()
    doctors = User.query.filter_by(role_id=doctor_role.id).all() if doctor_role else []
    return render_template('admin/doctors.html', doctors=doctors)

@admin_bp.route('/patients')
@login_required
@admin_required
def manage_patients():
    """Manage patients"""
    patient_role = Role.query.filter_by(name='patient').first()
    patients = User.query.filter_by(role_id=patient_role.id).all() if patient_role else []
    
    # Get patient data (medical records availability)
    patient_data = {}
    for patient in patients:
        has_predictions = Prediction.query.filter_by(user_id=patient.id).first() is not None
        patient_data[patient.id] = {
            'has_medical_record': has_predictions,
            'prediction_count': Prediction.query.filter_by(user_id=patient.id).count(),
            'appointment_count': Appointment.query.filter_by(patient_id=patient.id).count()
        }
    
    stats = {
        'total_patients': len(patients),
        'active_patients': len([p for p in patients if p.is_active]),
        'pending_approvals': len([p for p in patients if not p.is_active]),
        'total_records': Prediction.query.join(User).filter(User.role_id == patient_role.id).count() if patient_role else 0
    }
    
    return render_template('admin/patients.html', patients=patients, stats=stats, patient_data=patient_data)

@admin_bp.route('/nurses')
@login_required
@admin_required
def manage_nurses():
    """Manage nurses"""
    nurse_role = Role.query.filter_by(name='nurse').first()
    nurses = User.query.filter_by(role_id=nurse_role.id).all() if nurse_role else []
    return render_template('admin/nurses.html', nurses=nurses)

@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """View analytics with CSV data"""
    try:
        # Load CSV data
        csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'healthcare-dataset-stroke-data.csv')
        df = pd.read_csv(csv_path)
        
        # Age vs Stroke
        age_bins = pd.cut(df['age'], bins=[0, 30, 45, 60, 100], labels=['0-30', '31-45', '46-60', '60+'])
        age_stroke = df.groupby(age_bins)['stroke'].sum()
        age_vs_stroke = {
            'labels': ['0-30', '31-45', '46-60', '60+'],
            'data': [int(age_stroke.get('0-30', 0)), int(age_stroke.get('31-45', 0)), 
                     int(age_stroke.get('46-60', 0)), int(age_stroke.get('60+', 0))]
        }
        
        # Gender vs Stroke
        gender_stroke = df.groupby('gender')['stroke'].sum()
        gender_vs_stroke = {
            'Male': int(gender_stroke.get('Male', 0)),
            'Female': int(gender_stroke.get('Female', 0))
        }
        
        # Hypertension vs Stroke
        hypertension_vs_stroke = {
            'with_hypertension_stroke': int(df[df['hypertension'] == 1]['stroke'].sum()),
            'without_hypertension_stroke': int(df[df['hypertension'] == 0]['stroke'].sum())
        }
        
        # Heart Disease vs Stroke
        heart_disease_vs_stroke = {
            'with_heart_disease_stroke': int(df[df['heart_disease'] == 1]['stroke'].sum()),
            'without_heart_disease_stroke': int(df[df['heart_disease'] == 0]['stroke'].sum())
        }
        
        # Smoking Status vs Stroke
        smoking_stroke = df.groupby('smoking_status')['stroke'].sum()
        smoking_vs_stroke = {status: int(count) for status, count in smoking_stroke.items()}
        
        # BMI Categories vs Stroke
        df['bmi_category'] = pd.cut(df['bmi'], bins=[0, 18.5, 25, 30, 100], 
                                     labels=['Underweight', 'Normal', 'Overweight', 'Obese'])
        bmi_stroke = df.groupby('bmi_category')['stroke'].sum()
        bmi_vs_stroke = {category: int(count) for category, count in bmi_stroke.items()}
        
        # Glucose Average - Stroke vs No Stroke
        glucose_vs_stroke = {
            'stroke_avg': float(df[df['stroke'] == 1]['avg_glucose_level'].mean()),
            'no_stroke_avg': float(df[df['stroke'] == 0]['avg_glucose_level'].mean())
        }
        
        # Glucose Categories vs Stroke
        df['glucose_category'] = pd.cut(df['avg_glucose_level'], bins=[0, 100, 126, 200, 300], 
                                         labels=['Normal', 'Prediabetes', 'Diabetes', 'High'])
        glucose_cat_stroke = df.groupby('glucose_category')['stroke'].sum()
        glucose_categories_vs_stroke = {
            'labels': ['Normal', 'Prediabetes', 'Diabetes', 'High'],
            'data': [int(glucose_cat_stroke.get('Normal', 0)), int(glucose_cat_stroke.get('Prediabetes', 0)),
                     int(glucose_cat_stroke.get('Diabetes', 0)), int(glucose_cat_stroke.get('High', 0))]
        }
        
        # Prepare JSON data for Chart.js
        stroke_analytics_data = {
            'age_vs_stroke': age_vs_stroke,
            'gender_vs_stroke': gender_vs_stroke,
            'hypertension_vs_stroke': hypertension_vs_stroke,
            'heart_disease_vs_stroke': heart_disease_vs_stroke,
            'smoking_vs_stroke': smoking_vs_stroke,
            'bmi_vs_stroke': bmi_vs_stroke,
            'glucose_vs_stroke': glucose_vs_stroke,
            'glucose_categories_vs_stroke': glucose_categories_vs_stroke
        }
        
        import json
        stroke_analytics_json = json.dumps(stroke_analytics_data)
        
        # General statistics
        stroke_analytics = {
            'total_records': len(df),
            'stroke_distribution': {
                'stroke': int(df['stroke'].sum()),
                'no_stroke': int(len(df) - df['stroke'].sum())
            }
        }
        
        # Database prediction statistics
        stats = {
            'total_predictions': Prediction.query.count(),
            'high_risk': Prediction.query.filter_by(prediction=1).count(),
            'low_risk': Prediction.query.filter_by(prediction=0).count()
        }
        
        # Get recent predictions from database
        recent_predictions = Prediction.query.order_by(desc(Prediction.created_at)).limit(10).all()
        
    except Exception as e:
        print(f"Error loading analytics: {e}")
        import traceback
        traceback.print_exc()
        
        import json
        stroke_analytics_json = json.dumps({
            'age_vs_stroke': {'labels': [], 'data': []},
            'gender_vs_stroke': {'Male': 0, 'Female': 0},
            'hypertension_vs_stroke': {'with_hypertension_stroke': 0, 'without_hypertension_stroke': 0},
            'heart_disease_vs_stroke': {'with_heart_disease_stroke': 0, 'without_heart_disease_stroke': 0},
            'smoking_vs_stroke': {},
            'bmi_vs_stroke': {},
            'glucose_vs_stroke': {'stroke_avg': 0, 'no_stroke_avg': 0},
            'glucose_categories_vs_stroke': {'labels': [], 'data': []}
        })
        
        stroke_analytics = {
            'total_records': 0,
            'stroke_distribution': {'stroke': 0, 'no_stroke': 0}
        }
        stats = {'total_predictions': 0, 'high_risk': 0, 'low_risk': 0}
        recent_predictions = []
    
    return render_template('admin/analytics.html', 
                          stroke_analytics=stroke_analytics, 
                          stroke_analytics_json=stroke_analytics_json,
                          stats=stats, 
                          predictions=recent_predictions)

@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """View system reports"""
    try:
        # Get all users
        all_users = User.query.all()
        
        # User statistics
        stats = {
            'total_users': len(all_users),
            'active_users': len([u for u in all_users if u.is_active]),
            'inactive_users': len([u for u in all_users if not u.is_active]),
            'total_doctors': User.query.join(Role).filter(Role.name == 'doctor').count(),
            'total_nurses': User.query.join(Role).filter(Role.name == 'nurse').count(),
            'total_patients': User.query.join(Role).filter(Role.name == 'patient').count(),
            'total_admins': User.query.join(Role).filter(Role.name == 'admin').count(),
            'total_appointments': Appointment.query.count(),
            'pending_appointments': Appointment.query.filter_by(status='pending').count(),
            'confirmed_appointments': Appointment.query.filter_by(status='confirmed').count(),
            'total_predictions': Prediction.query.count(),
            'high_risk_predictions': Prediction.query.filter_by(prediction=1).count()
        }
        
        # Recent data
        appointments = Appointment.query.order_by(desc(Appointment.created_at)).limit(10).all()
        predictions = Prediction.query.order_by(desc(Prediction.created_at)).limit(10).all()
        
    except Exception as e:
        print(f"Error loading reports: {e}")
        import traceback
        traceback.print_exc()
        stats = {}
        appointments = []
        predictions = []
    
    return render_template('admin/reports.html', stats=stats, appointments=appointments, predictions=predictions)

@admin_bp.route('/pending-approvals')
@login_required
@admin_required
def pending_approvals():
    """View pending user approvals"""
    pending_users = User.query.filter_by(is_active=False).all()
    return render_template('admin/pending_approvals.html', pending_users=pending_users)