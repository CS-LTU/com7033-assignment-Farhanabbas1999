from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role, Appointment, Prediction
from app import db
from sqlalchemy import desc, or_

doctor_bp = Blueprint('doctor', __name__, url_prefix='/doctor')

def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'doctor':
            flash('You need to be a doctor to access this page!', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@doctor_bp.route('/dashboard')
@login_required
@doctor_required
def dashboard():
    """Doctor dashboard"""
    try:
        patient_role = Role.query.filter_by(name='patient').first()
        total_patients = User.query.filter_by(role_id=patient_role.id, is_active=True).count() if patient_role else 0
        
        stats = {
            'total_patients': total_patients,
            'total_appointments': Appointment.query.filter_by(doctor_id=current_user.id).count(),
            'pending_appointments': Appointment.query.filter_by(doctor_id=current_user.id, status='pending').count(),
            'high_risk_patients': Prediction.query.filter_by(prediction=1).count()
        }
    except Exception as e:
        print(f"Error: {e}")
        stats = {
            'total_patients': 0,
            'total_appointments': 0,
            'pending_appointments': 0,
            'high_risk_patients': 0
        }
    
    return render_template('doctor/dashboard.html', stats=stats)

@doctor_bp.route('/patients')
@login_required
@doctor_required
def patients():
    """View all patients"""
    try:
        patient_role = Role.query.filter_by(name='patient').first()
        patients = User.query.filter_by(role_id=patient_role.id, is_active=True).all() if patient_role else []
    except Exception as e:
        print(f"Error: {e}")
        patients = []
    
    return render_template('doctor/patients.html', patients=patients)

@doctor_bp.route('/appointments')
@login_required
@doctor_required
def appointments():
    """View doctor's appointments"""
    appointments = Appointment.query.filter_by(
        doctor_id=current_user.id
    ).order_by(desc(Appointment.date)).all()
    
    return render_template('doctor/appointments.html', appointments=appointments)

@doctor_bp.route('/appointments/<int:appointment_id>/confirm', methods=['POST'])
@login_required
@doctor_required
def confirm_appointment(appointment_id):
    """Confirm an appointment"""
    try:
        appointment = Appointment.query.filter_by(
            id=appointment_id,
            doctor_id=current_user.id
        ).first()
        
        if appointment:
            appointment.status = 'confirmed'
            db.session.commit()
            flash('Appointment confirmed successfully!', 'success')
        else:
            flash('Appointment not found', 'danger')
    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()
        flash('Error confirming appointment', 'danger')
    
    return redirect(url_for('doctor.appointments'))

@doctor_bp.route('/appointments/<int:appointment_id>/cancel', methods=['POST'])
@login_required
@doctor_required
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    try:
        appointment = Appointment.query.filter_by(
            id=appointment_id,
            doctor_id=current_user.id
        ).first()
        
        if appointment:
            appointment.status = 'cancelled'
            db.session.commit()
            flash('Appointment cancelled', 'info')
        else:
            flash('Appointment not found', 'danger')
    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()
        flash('Error cancelling appointment', 'danger')
    
    return redirect(url_for('doctor.appointments'))

@doctor_bp.route('/analytics')
@login_required
@doctor_required
def analytics():
    """View analytics"""
    try:
        stats = {
            'total_predictions': Prediction.query.count(),
            'high_risk': Prediction.query.filter_by(prediction=1).count(),
            'low_risk': Prediction.query.filter_by(prediction=0).count(),
            'male_patients': Prediction.query.filter_by(gender='Male').count(),
            'female_patients': Prediction.query.filter_by(gender='Female').count()
        }
    except Exception as e:
        print(f"Error: {e}")
        stats = {
            'total_predictions': 0,
            'high_risk': 0,
            'low_risk': 0,
            'male_patients': 0,
            'female_patients': 0
        }
    
    return render_template('doctor/analytics.html', stats=stats)

@doctor_bp.route('/patients/add', methods=['GET', 'POST'])
@login_required
@doctor_required
def add_patient():
    """Add a new patient"""
    if request.method == 'POST':
        flash('Patient creation should be done through user registration', 'info')
        return redirect(url_for('doctor.patients'))
    
    return render_template('doctor/add_patient.html')

@doctor_bp.route('/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@login_required
@doctor_required
def edit_patient(patient_id):
    """Edit patient information"""
    patient = User.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        try:
            patient.username = request.form.get('username', patient.username)
            patient.email = request.form.get('email', patient.email)
            db.session.commit()
            flash('Patient updated successfully!', 'success')
            return redirect(url_for('doctor.patients'))
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash('Error updating patient', 'danger')
    
    return render_template('doctor/edit_patient.html', user=patient)