from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role
from app import db, mongo

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
        # Get statistics
        patient_role = Role.query.filter_by(name='patient').first()
        total_patients = User.query.filter_by(role_id=patient_role.id, is_active=True).count() if patient_role else 0
        
        stats = {
            'total_patients': total_patients,
            'total_appointments': 0,
            'pending_tasks': 0,
            'completed_today': 0
        }
        
        if mongo.db is not None:
            try:
                stats['total_appointments'] = mongo.db.appointments.count_documents({'status': {'$ne': 'cancelled'}})
                stats['pending_tasks'] = mongo.db.appointments.count_documents({'status': 'pending'})
                today_str = mongo.db.appointments.count_documents({'date': {'$regex': '^2025-12-10'}})
                stats['completed_today'] = today_str
            except Exception as e:
                print(f"MongoDB error: {e}")
        
        # Get recent patients
        recent_patients = []
        if patient_role:
            patients = User.query.filter_by(role_id=patient_role.id, is_active=True).order_by(User.created_at.desc()).limit(5).all()
            recent_patients = patients
        
        # Get today's appointments
        today_appointments = []
        if mongo.db is not None:
            try:
                appointments = list(mongo.db.appointments.find().sort('date', 1).limit(5))
                for apt in appointments:
                    if 'patient_id' in apt:
                        patient = User.query.get(apt['patient_id'])
                        apt['patient'] = patient
                    if 'doctor_id' in apt:
                        doctor = User.query.get(apt['doctor_id'])
                        apt['doctor'] = doctor
                    today_appointments.append(apt)
            except Exception as e:
                print(f"MongoDB error: {e}")
        
    except Exception as e:
        print(f"Error loading dashboard: {str(e)}")
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
    patient_role = Role.query.filter_by(name='patient').first()
    patients = User.query.filter_by(role_id=patient_role.id, is_active=True).all() if patient_role else []
    
    return render_template('nurse/patients.html', patients=patients)

@nurse_bp.route('/appointments')
@login_required
@nurse_required
def appointments():
    """View all appointments"""
    appointments = []
    
    if mongo.db is not None:
        try:
            apts = list(mongo.db.appointments.find().sort('date', -1))
            
            for apt in apts:
                if 'patient_id' in apt:
                    patient = User.query.get(apt['patient_id'])
                    apt['patient'] = patient
                if 'doctor_id' in apt:
                    doctor = User.query.get(apt['doctor_id'])
                    apt['doctor'] = doctor
                apt['_id'] = str(apt['_id'])
                appointments.append(apt)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('nurse/appointments.html', appointments=appointments)