from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from app.models import User
from app import db, mongo
from datetime import datetime
from bson.objectid import ObjectId

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
        stats = {
            'total_appointments': 0,
            'upcoming_appointments': 0,
            'completed_checkups': 0,
            'risk_level': 'Not Assessed'
        }
        
        if mongo.db is not None:
            try:
                # Get appointment stats
                stats['total_appointments'] = mongo.db.appointments.count_documents({'patient_id': current_user.id})
                stats['upcoming_appointments'] = mongo.db.appointments.count_documents({
                    'patient_id': current_user.id,
                    'status': {'$in': ['pending', 'confirmed']}
                })
                stats['completed_checkups'] = mongo.db.appointments.count_documents({
                    'patient_id': current_user.id,
                    'status': 'completed'
                })
                
                # Get last prediction
                last_prediction = mongo.db.predictions.find_one(
                    {'user_id': current_user.id},
                    sort=[('created_at', -1)]
                )
                
                if last_prediction:
                    risk = last_prediction.get('prediction', 0)
                    stats['risk_level'] = 'High Risk' if risk == 1 else 'Low Risk'
                    stats['last_prediction'] = last_prediction
                
            except Exception as e:
                print(f"MongoDB error: {e}")
        
        # Get upcoming appointments
        upcoming_appointments = []
        if mongo.db is not None:
            try:
                apts = list(mongo.db.appointments.find({
                    'patient_id': current_user.id
                }).sort('date', 1).limit(5))
                
                for apt in apts:
                    if 'doctor_id' in apt:
                        doctor = User.query.get(apt['doctor_id'])
                        apt['doctor'] = doctor
                    apt['_id'] = str(apt['_id'])
                    upcoming_appointments.append(apt)
            except Exception as e:
                print(f"MongoDB error: {e}")
        
        # Get recent predictions
        recent_predictions = []
        if mongo.db is not None:
            try:
                predictions = list(mongo.db.predictions.find({
                    'user_id': current_user.id
                }).sort('created_at', -1).limit(5))
                
                for pred in predictions:
                    pred['_id'] = str(pred['_id'])
                    recent_predictions.append(pred)
            except Exception as e:
                print(f"MongoDB error: {e}")
        
    except Exception as e:
        print(f"Error loading dashboard: {str(e)}")
        stats = {'total_appointments': 0, 'upcoming_appointments': 0, 'completed_checkups': 0, 'risk_level': 'Not Assessed'}
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
    """View patient's appointments"""
    appointments = []
    
    if mongo.db is not None:
        try:
            apts = list(mongo.db.appointments.find({
                'patient_id': current_user.id
            }).sort('date', -1))
            
            for apt in apts:
                if 'doctor_id' in apt:
                    doctor = User.query.get(apt['doctor_id'])
                    apt['doctor'] = doctor
                apt['_id'] = str(apt['_id'])
                appointments.append(apt)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('patient/appointments.html', appointments=appointments)

@patient_bp.route('/predictions')
@login_required
@patient_required
def predictions():
    """View patient's stroke predictions"""
    predictions = []
    
    if mongo.db is not None:
        try:
            preds = list(mongo.db.predictions.find({
                'user_id': current_user.id
            }).sort('created_at', -1))
            
            for pred in preds:
                pred['_id'] = str(pred['_id'])
                predictions.append(pred)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('patient/predictions.html', predictions=predictions)

@patient_bp.route('/medical-records')
@login_required
@patient_required
def medical_records():
    """View patient's medical records"""
    records = []
    
    if mongo.db is not None:
        try:
            recs = list(mongo.db.medical_records.find({
                'patient_id': current_user.id
            }).sort('created_at', -1))
            
            for rec in recs:
                rec['_id'] = str(rec['_id'])
                records.append(rec)
        except Exception as e:
            print(f"MongoDB error: {e}")
    
    return render_template('patient/medical_records.html', records=records)