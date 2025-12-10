from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role, Appointment, Prediction
from app import db
from datetime import datetime
from sqlalchemy import desc

patient_bp = Blueprint('patient', __name__, url_prefix='/patient')

def patient_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'patient':
            flash('You need to be a patient to access this page!', 'danger')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

@patient_bp.route('/dashboard')
@login_required
@patient_required
def dashboard():
    """Patient dashboard"""
    try:
        # Get statistics
        stats = {
            'total_appointments': Appointment.query.filter_by(patient_id=current_user.id).count(),
            'upcoming_appointments': Appointment.query.filter_by(
                patient_id=current_user.id,
                status='confirmed'
            ).count(),
            'completed_checkups': Appointment.query.filter_by(
                patient_id=current_user.id,
                status='completed'
            ).count(),
            'risk_level': 'Not Assessed'
        }
        
        # Get upcoming appointments
        upcoming_appointments = Appointment.query.filter_by(
            patient_id=current_user.id
        ).order_by(Appointment.date.desc()).limit(5).all()
        
        # Get recent predictions
        recent_predictions = Prediction.query.filter_by(
            user_id=current_user.id
        ).order_by(desc(Prediction.created_at)).limit(5).all()
        
        # Get latest risk level
        if recent_predictions:
            latest = recent_predictions[0]
            stats['risk_level'] = 'High Risk' if latest.prediction == 1 else 'Low Risk'
        
    except Exception as e:
        print(f"Error: {e}")
        stats = {
            'total_appointments': 0,
            'upcoming_appointments': 0,
            'completed_checkups': 0,
            'risk_level': 'Not Assessed'
        }
        upcoming_appointments = []
        recent_predictions = []
    
    return render_template('patient/dashboard.html',
                         stats=stats,
                         upcoming_appointments=upcoming_appointments,
                         recent_predictions=recent_predictions)

@patient_bp.route('/appointments')
@login_required
@patient_required
def appointments():
    """View patient appointments"""
    appointments = Appointment.query.filter_by(
        patient_id=current_user.id
    ).order_by(desc(Appointment.date)).all()
    
    # Get list of doctors for booking
    doctor_role = Role.query.filter_by(name='doctor').first()
    doctors = User.query.filter_by(role_id=doctor_role.id, is_active=True).all() if doctor_role else []
    
    return render_template('patient/appointments.html', appointments=appointments, doctors=doctors)

@patient_bp.route('/appointments/book', methods=['POST'])
@login_required
@patient_required
def book_appointment():
    """Book a new appointment"""
    try:
        doctor_id = request.form.get('doctor_id')
        date = request.form.get('date')
        time = request.form.get('time')
        reason = request.form.get('reason', '')
        
        print(f"Booking appointment - Doctor: {doctor_id}, Date: {date}, Time: {time}")
        
        # Validation
        if not doctor_id or not date or not time:
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('patient.appointments'))
        
        # Validate doctor
        doctor = User.query.get(int(doctor_id))
        if not doctor or doctor.role.name != 'doctor':
            flash('Invalid doctor selected', 'danger')
            return redirect(url_for('patient.appointments'))
        
        # Validate date
        appointment_date = datetime.strptime(date, '%Y-%m-%d').date()
        if appointment_date < datetime.now().date():
            flash('Please select a future date', 'danger')
            return redirect(url_for('patient.appointments'))
        
        # Create appointment
        appointment = Appointment(
            patient_id=current_user.id,
            doctor_id=int(doctor_id),
            date=date,
            time=time,
            reason=reason.strip(),
            status='pending'
        )
        
        db.session.add(appointment)
        db.session.commit()
        
        flash('Appointment booked successfully! Waiting for doctor confirmation.', 'success')
            
    except Exception as e:
        print(f"Error booking appointment: {e}")
        db.session.rollback()
        flash('Error booking appointment. Please try again.', 'danger')
    
    return redirect(url_for('patient.appointments'))

@patient_bp.route('/appointments/<int:appointment_id>/cancel', methods=['POST'])
@login_required
@patient_required
def cancel_appointment(appointment_id):
    """Cancel an appointment"""
    try:
        appointment = Appointment.query.filter_by(
            id=appointment_id,
            patient_id=current_user.id
        ).first()
        
        if appointment:
            appointment.status = 'cancelled'
            db.session.commit()
            flash('Appointment cancelled successfully', 'success')
        else:
            flash('Appointment not found', 'danger')
    except Exception as e:
        print(f"Error: {e}")
        db.session.rollback()
        flash('Error cancelling appointment', 'danger')
    
    return redirect(url_for('patient.appointments'))

@patient_bp.route('/predictions')
@login_required
@patient_required
def predictions():
    """View patient predictions"""
    predictions = Prediction.query.filter_by(
        user_id=current_user.id
    ).order_by(desc(Prediction.created_at)).all()
    
    return render_template('patient/predictions.html', predictions=predictions)

@patient_bp.route('/medical-records')
@login_required
@patient_required
def medical_records():
    """View medical records"""
    records = Prediction.query.filter_by(
        user_id=current_user.id
    ).order_by(desc(Prediction.created_at)).all()
    
    return render_template('patient/medical_records.html', records=records)

@patient_bp.route('/profile')
@login_required
@patient_required
def view_profile():
    """View patient profile"""
    # Get patient's predictions and appointments for profile summary
    predictions = Prediction.query.filter_by(user_id=current_user.id).order_by(desc(Prediction.created_at)).limit(5).all()
    appointments = Appointment.query.filter_by(patient_id=current_user.id).order_by(desc(Appointment.date)).limit(5).all()
    
    return render_template('patient/profile.html', 
                         user=current_user,
                         predictions=predictions,
                         appointments=appointments)

@patient_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@patient_required
def edit_profile():
    """Edit patient profile"""
    if request.method == 'POST':
        try:
            current_user.username = request.form.get('username', current_user.username)
            current_user.email = request.form.get('email', current_user.email)
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('patient.view_profile'))
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash('Error updating profile', 'danger')
    
    return render_template('patient/edit_profile.html', user=current_user)