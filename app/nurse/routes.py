from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.extensions import mongo
from bson.objectid import ObjectId
import datetime

nurse_bp = Blueprint('nurse', __name__)

@nurse_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role.name != 'nurse':
        flash('Access denied', 'danger')
        return redirect(url_for('main.index'))
    
    patients = list(mongo.db.patients.find())
    
    stats = {
        'total_patients': len(patients),
        'today_patients': 5,
        'pending_vitals': 3
    }
    
    return render_template('nurse/dashboard.html', stats=stats, patients=patients)

@nurse_bp.route('/patients')
@login_required
def patients():
    patients = list(mongo.db.patients.find())
    return render_template('nurse/patients.html', patients=patients)

@nurse_bp.route('/patient/<patient_id>/vitals', methods=['GET', 'POST'])
@login_required
def add_vitals(patient_id):
    patient = mongo.db.patients.find_one({'_id': ObjectId(patient_id)})
    
    if request.method == 'POST':
        vitals = {
            'blood_pressure': request.form.get('blood_pressure'),
            'heart_rate': request.form.get('heart_rate'),
            'temperature': request.form.get('temperature'),
            'oxygen_level': request.form.get('oxygen_level'),
            'recorded_by': current_user.id,
            'timestamp': datetime.datetime.utcnow()
        }
        
        mongo.db.patients.update_one(
            {'_id': ObjectId(patient_id)},
            {'$push': {'vitals': vitals}}
        )
        flash('Vitals recorded successfully', 'success')
        return redirect(url_for('nurse.patients'))
    
    return render_template('nurse/add_vitals.html', patient=patient)

@nurse_bp.route('/appointments')
@login_required
def appointments():
    appointments = list(mongo.db.appointments.find())
    return render_template('nurse/appointments.html', appointments=appointments)