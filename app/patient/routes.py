from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.extensions import mongo
from bson.objectid import ObjectId
import datetime

patient_bp = Blueprint('patient', __name__)

@patient_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role.name != 'patient':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))
    
    # Get patient record from MongoDB
    patient = mongo.db.patients.find_one({'user_id': current_user.id})
    
    stats = {
        'upcoming_appointments': 2,
        'last_visit': 'Nov 15, 2025',
        'health_status': 'Stable'
    }
    
    return render_template('patient/dashboard.html', stats=stats, patient=patient)

@patient_bp.route('/records')
@login_required
def records():
    patient = mongo.db.patients.find_one({'user_id': current_user.id})
    return render_template('patient/records.html', patient=patient)

@patient_bp.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        appointment_date = request.form.get('appointment_date')
        
        appointment = {
            'patient_id': current_user.id,
            'doctor_id': int(doctor_id),
            'date': appointment_date,
            'status': 'Pending',
            'created_at': datetime.datetime.utcnow()
        }
        
        mongo.db.appointments.insert_one(appointment)
        flash('Appointment booked successfully', 'success')
        return redirect(url_for('patient.dashboard'))
    
    return render_template('patient/book_appointment.html')

@patient_bp.route('/profile')
@login_required
def profile():
    patient = mongo.db.patients.find_one({'user_id': current_user.id})
    return render_template('patient/profile.html', patient=patient)