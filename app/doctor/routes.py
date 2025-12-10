from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role
from app import db, mongo
import pandas as pd
import json
import os

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
    # Get statistics
    stats = {
        'total_patients': 0,
        'pending_appointments': 0,
        'today_appointments': 0,
        'total_predictions': 0
    }
    
    if mongo.db is not None:
        try:
            # Count appointments for this doctor
            stats['pending_appointments'] = mongo.db.appointments.count_documents({
                'doctor_id': current_user.id,
                'status': 'pending'
            })
            stats['today_appointments'] = mongo.db.appointments.count_documents({
                'doctor_id': current_user.id,
                'date': pd.Timestamp.now().strftime('%Y-%m-%d')
            })
            stats['total_predictions'] = mongo.db.predictions.count_documents({})
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    # Get patient count
    patient_role = Role.query.filter_by(name='patient').first()
    if patient_role:
        stats['total_patients'] = User.query.filter_by(role_id=patient_role.id, is_active=True).count()
    
    return render_template('doctor/dashboard.html', stats=stats)

@doctor_bp.route('/appointments')
@login_required
@doctor_required
def appointments():
    """View doctor's appointments"""
    appointments = []
    
    if mongo.db is not None:
        try:
            # Get appointments for this doctor
            apts = list(mongo.db.appointments.find({
                'doctor_id': current_user.id
            }).sort('date', -1))
            
            for apt in apts:
                patient = User.query.get(apt.get('patient_id'))
                apt['patient'] = patient
                apt['_id'] = str(apt['_id'])
                appointments.append(apt)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('doctor/appointments.html', appointments=appointments)

@doctor_bp.route('/patients')
@login_required
@doctor_required
def patients():
    """View all patients"""
    patient_role = Role.query.filter_by(name='patient').first()
    patients = User.query.filter_by(role_id=patient_role.id, is_active=True).all() if patient_role else []
    
    return render_template('doctor/patients.html', patients=patients)

@doctor_bp.route('/analytics')
@login_required
@doctor_required
def analytics():
    """View stroke prediction analytics"""
    try:
        # Path to CSV file
        csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'healthcare-dataset-stroke-data.csv')
        
        # Read CSV
        df = pd.read_csv(csv_path)
        
        # Calculate analytics (reuse admin function)
        from app.admin.routes import calculate_stroke_analytics
        stroke_analytics = calculate_stroke_analytics(df)
        
        # Convert to JSON for JavaScript
        stroke_analytics_json = json.dumps(stroke_analytics)
        
        # Get stats
        stats = {
            'total_predictions': 0
        }
        
        if mongo.db is not None:
            try:
                stats['total_predictions'] = mongo.db.predictions.count_documents({})
            except:
                pass
        
        return render_template('doctor/analytics.html', 
                             stroke_analytics=stroke_analytics,
                             stroke_analytics_json=stroke_analytics_json,
                             stats=stats)
    except Exception as e:
        flash(f'Error loading analytics: {str(e)}', 'danger')
        return redirect(url_for('doctor.dashboard'))