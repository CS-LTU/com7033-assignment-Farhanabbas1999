from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.extensions import db, mongo
from app.models import User, Role
from bson.objectid import ObjectId

doctor_bp = Blueprint('doctor', __name__)

@doctor_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role.name != 'doctor':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))
    
    # Get assigned patients from MongoDB
    patients = list(mongo.db.patients.find({'assigned_doctor': current_user.id}))
    
    stats = {
        'total_patients': len(patients),
        'today_patients': len([p for p in patients if 'last_visit' in p]),
        'today_appointments': 3
    }
    
    appointments = [
        {'id': 1, 'patient': 'John Doe', 'time': '09:00 AM', 'status': 'Confirmed'},
        {'id': 2, 'patient': 'Jane Smith', 'time': '10:30 AM', 'status': 'Pending'},
        {'id': 3, 'patient': 'Bob Johnson', 'time': '02:00 PM', 'status': 'Confirmed'},
    ]
    
    return render_template('doctor/dashboard.html', stats=stats, appointments=appointments, patients=patients)

@doctor_bp.route('/patients')
@login_required
def patients():
    patients = list(mongo.db.patients.find({'assigned_doctor': current_user.id}))
    return render_template('doctor/patients.html', patients=patients)

@doctor_bp.route('/patient/<patient_id>')
@login_required
def patient_detail(patient_id):
    patient = mongo.db.patients.find_one({'_id': ObjectId(patient_id)})
    if not patient:
        flash('Patient not found', 'danger')
        return redirect(url_for('doctor.patients'))
    
    return render_template('doctor/patient_detail.html', patient=patient)

@doctor_bp.route('/patient/<patient_id>/update-notes', methods=['POST'])
@login_required
def update_notes(patient_id):
    notes = request.form.get('notes')
    mongo.db.patients.update_one(
        {'_id': ObjectId(patient_id)},
        {'$set': {'medical_notes': notes, 'last_updated': __import__('datetime').datetime.utcnow()}}
    )
    flash('Notes updated successfully', 'success')
    return redirect(url_for('doctor.patient_detail', patient_id=patient_id))

@doctor_bp.route('/appointments')
@login_required
def appointments():
    return render_template('doctor/appointments.html')

@doctor_bp.route('/profile')
@login_required
def profile():
    return render_template('doctor/profile.html')

@doctor_bp.route('/payments')
@login_required
def payments():
    return render_template('doctor/payments.html')