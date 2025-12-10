from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role, Appointment, Prediction
from app import db
from sqlalchemy import desc
from datetime import datetime

nurse_bp = Blueprint('nurse', __name__, url_prefix='/nurse')

def nurse_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'nurse':
            flash('You need to be a nurse to access this page!', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@nurse_bp.route('/dashboard')
@login_required
@nurse_required
def dashboard():
    """Nurse dashboard"""
    try:
        patient_role = Role.query.filter_by(name='patient').first()
        total_patients = User.query.filter_by(role_id=patient_role.id, is_active=True).count() if patient_role else 0
        
        stats = {
            'total_patients': total_patients,
            'total_appointments': Appointment.query.count(),
            'pending_tasks': Appointment.query.filter_by(status='pending').count(),
            'completed_today': 0
        }
        
        # Get recent patients
        recent_patients = User.query.filter_by(role_id=patient_role.id, is_active=True).order_by(desc(User.created_at)).limit(5).all() if patient_role else []
        
        # Get today's appointments
        today = datetime.now().strftime('%Y-%m-%d')
        today_appointments = Appointment.query.filter_by(date=today).limit(5).all()
        
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        stats = {'total_patients': 0, 'total_appointments': 0, 'pending_tasks': 0, 'completed_today': 0}
        recent_patients = []
        today_appointments = []
    
    return render_template('nurse/dashboard.html', 
                         stats=stats,
                         recent_patients=recent_patients,
                         today_appointments=today_appointments)

@nurse_bp.route('/patients')
@login_required
@nurse_required
def patients():
    """View all patients"""
    try:
        patient_role = Role.query.filter_by(name='patient').first()
        patients = User.query.filter_by(role_id=patient_role.id, is_active=True).all() if patient_role else []
        
        stats = {
            'total_patients': len(patients),
            'active_patients': len([p for p in patients if p.is_active]),
            'recent_patients': len([p for p in patients if p.created_at])
        }
    except Exception as e:
        print(f"Error loading patients: {e}")
        patients = []
        stats = {'total_patients': 0, 'active_patients': 0, 'recent_patients': 0}
    
    return render_template('nurse/patients.html', patients=patients, stats=stats)

@nurse_bp.route('/appointments')
@login_required
@nurse_required
def appointments():
    """View all appointments"""
    appointments = Appointment.query.order_by(desc(Appointment.date)).all()
    
    return render_template('nurse/appointments.html', appointments=appointments)

@nurse_bp.route('/patients/<int:patient_id>')
@login_required
@nurse_required
def view_patient(patient_id):
    """View patient details"""
    patient = User.query.get_or_404(patient_id)
    
    # Get patient's predictions and appointments
    predictions = Prediction.query.filter_by(user_id=patient_id).order_by(desc(Prediction.created_at)).all()
    appointments = Appointment.query.filter_by(patient_id=patient_id).order_by(desc(Appointment.date)).all()
    
    return render_template('nurse/patient_detail.html',
                         user=patient,
                         predictions=predictions,
                         appointments=appointments)

@nurse_bp.route('/patients/<int:patient_id>/vitals', methods=['GET', 'POST'])
@login_required
@nurse_required
def update_vitals(patient_id):
    """Update patient vitals"""
    patient = User.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        flash('Vitals recording functionality to be implemented', 'info')
        return redirect(url_for('nurse.view_patient', patient_id=patient_id))
    
    return render_template('nurse/update_vitals.html', user=patient)