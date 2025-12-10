from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from app.models import User, Role
from app import db, mongo
from datetime import datetime
from bson.objectid import ObjectId
import os
import joblib

doctor_bp = Blueprint('doctor', __name__, url_prefix='/doctor')

def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'doctor':
            flash('You need to be logged in as a doctor to access this page.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@doctor_bp.route('/dashboard')
@login_required
@doctor_required
def dashboard():
    """Doctor dashboard"""
    try:
        # Get statistics
        total_patients = mongo.db.patients.count_documents({}) if mongo.db is not None else 0
        total_appointments = mongo.db.appointments.count_documents({'doctor_id': current_user.id}) if mongo.db is not None else 0
        pending_appointments = mongo.db.appointments.count_documents({'doctor_id': current_user.id, 'status': 'pending'}) if mongo.db is not None else 0
        high_risk_patients = mongo.db.predictions.count_documents({'prediction': 1}) if mongo.db is not None else 0
        
        stats = {
            'total_patients': total_patients,
            'total_appointments': total_appointments,
            'pending_appointments': pending_appointments,
            'high_risk_patients': high_risk_patients
        }
        
        # Get recent patients
        recent_patients = list(mongo.db.patients.find().sort('created_at', -1).limit(5)) if mongo.db is not None else []
        for patient in recent_patients:
            if 'user_id' in patient:
                user = User.query.get(patient['user_id'])
                patient['user'] = user
                # Get last prediction
                last_prediction = mongo.db.predictions.find_one({'user_id': patient['user_id']}, sort=[('created_at', -1)])
                patient['last_prediction_risk'] = last_prediction.get('prediction') if last_prediction else None
        
        # Get upcoming appointments
        upcoming_appointments = list(mongo.db.appointments.find({'doctor_id': current_user.id}).sort('date', 1).limit(5)) if mongo.db is not None else []
        for appointment in upcoming_appointments:
            if 'patient_id' in appointment:
                patient = User.query.get(appointment['patient_id'])
                appointment['patient'] = patient
        
    except Exception as e:
        print(f"Error loading dashboard: {str(e)}")
        stats = {'total_patients': 0, 'total_appointments': 0, 'pending_appointments': 0, 'high_risk_patients': 0}
        recent_patients = []
        upcoming_appointments = []
    
    return render_template('doctor/dashboard.html', 
                         stats=stats, 
                         recent_patients=recent_patients,
                         upcoming_appointments=upcoming_appointments)

@doctor_bp.route('/search-patient')
@login_required
@doctor_required
def search_patient():
    """Search for patients by name"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify({'patients': []})
    
    try:
        # Search in MongoDB patients collection
        patients = list(mongo.db.patients.find()) if mongo.db is not None else []
        
        # Filter by name and add user data
        matching_patients = []
        for patient in patients:
            if 'user_id' in patient:
                user = User.query.get(patient['user_id'])
                if user and query.lower() in user.username.lower():
                    matching_patients.append({
                        'id': str(patient['_id']),
                        'name': user.username,
                        'email': user.email,
                        'age': patient.get('age', 'N/A'),
                        'gender': patient.get('gender', 'N/A')
                    })
        
        return jsonify({'patients': matching_patients})
    except Exception as e:
        print(f"Error searching patients: {str(e)}")
        return jsonify({'patients': [], 'error': str(e)})

@doctor_bp.route('/patient/<patient_id>/stroke-prediction')
@login_required
@doctor_required
def patient_stroke_prediction(patient_id):
    """View patient's stroke prediction with chart"""
    try:
        # Get patient from MongoDB
        patient = mongo.db.patients.find_one({'_id': ObjectId(patient_id)})
        
        if not patient:
            flash('Patient not found', 'danger')
            return redirect(url_for('doctor.dashboard'))
        
        # Get user info
        user = None
        if 'user_id' in patient:
            user = User.query.get(patient['user_id'])
        
        # Get or calculate stroke prediction
        prediction_data = mongo.db.predictions.find_one({'patient_id': patient_id})
        
        if not prediction_data:
            # Calculate new prediction
            prediction_data = calculate_stroke_prediction(patient)
            
            # Save to MongoDB
            if prediction_data and mongo.db is not None:
                prediction_data['patient_id'] = patient_id
                prediction_data['doctor_id'] = current_user.id
                prediction_data['created_at'] = datetime.utcnow()
                mongo.db.predictions.insert_one(prediction_data)
        
        # Calculate risk factors breakdown
        risk_factors = calculate_risk_factors(patient)
        
        return render_template('doctor/patient_prediction.html',
                             patient=patient,
                             user=user,
                             prediction=prediction_data,
                             risk_factors=risk_factors)
        
    except Exception as e:
        print(f"Error loading stroke prediction: {str(e)}")
        flash('Error loading patient data', 'danger')
        return redirect(url_for('doctor.dashboard'))

def calculate_stroke_prediction(patient):
    """Calculate stroke prediction using ML model or rule-based system"""
    try:
        # Try to load ML model
        model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'stroke_model.pkl')
        
        if os.path.exists(model_path):
            model = joblib.load(model_path)
            
            # Prepare features
            features = prepare_features(patient)
            prediction = model.predict([features])[0]
            probability = model.predict_proba([features])[0]
            
            return {
                'prediction': int(prediction),
                'probability': float(probability[1]),
                'risk_level': 'High' if probability[1] > 0.7 else 'Medium' if probability[1] > 0.4 else 'Low',
                'confidence': float(probability[1])
            }
        else:
            # Use rule-based system
            return rule_based_prediction(patient)
            
    except Exception as e:
        print(f"Error calculating prediction: {str(e)}")
        return rule_based_prediction(patient)

def rule_based_prediction(patient):
    """Rule-based stroke risk assessment"""
    risk_score = 0
    
    # Age risk
    age = patient.get('age', 0)
    if age > 65:
        risk_score += 30
    elif age > 55:
        risk_score += 20
    elif age > 45:
        risk_score += 10
    
    # Hypertension
    if patient.get('hypertension', 0) == 1:
        risk_score += 25
    
    # Heart disease
    if patient.get('heart_disease', 0) == 1:
        risk_score += 25
    
    # BMI
    bmi = patient.get('bmi', 0)
    if bmi > 30:
        risk_score += 15
    elif bmi > 25:
        risk_score += 10
    
    # Glucose level
    glucose = patient.get('avg_glucose_level', 0)
    if glucose > 200:
        risk_score += 15
    elif glucose > 140:
        risk_score += 10
    
    # Smoking
    smoking = patient.get('smoking_status', '')
    if smoking in ['smokes', 'formerly smoked']:
        risk_score += 10
    
    probability = min(risk_score / 100, 0.95)
    
    return {
        'prediction': 1 if risk_score > 50 else 0,
        'probability': probability,
        'risk_level': 'High' if risk_score > 70 else 'Medium' if risk_score > 40 else 'Low',
        'confidence': probability,
        'risk_score': risk_score
    }

def calculate_risk_factors(patient):
    """Calculate individual risk factor contributions"""
    risk_factors = []
    
    # Age
    age = patient.get('age', 0)
    age_risk = 0
    if age > 65:
        age_risk = 80
    elif age > 55:
        age_risk = 60
    elif age > 45:
        age_risk = 40
    else:
        age_risk = 20
    risk_factors.append({'name': 'Age', 'value': age_risk, 'color': '#ff6384'})
    
    # Hypertension
    hypertension = patient.get('hypertension', 0)
    risk_factors.append({'name': 'Hypertension', 'value': 85 if hypertension else 15, 'color': '#36a2eb'})
    
    # Heart Disease
    heart_disease = patient.get('heart_disease', 0)
    risk_factors.append({'name': 'Heart Disease', 'value': 90 if heart_disease else 10, 'color': '#ffce56'})
    
    # BMI
    bmi = patient.get('bmi', 0)
    bmi_risk = 0
    if bmi > 30:
        bmi_risk = 75
    elif bmi > 25:
        bmi_risk = 50
    else:
        bmi_risk = 25
    risk_factors.append({'name': 'BMI', 'value': bmi_risk, 'color': '#4bc0c0'})
    
    # Glucose
    glucose = patient.get('avg_glucose_level', 0)
    glucose_risk = 0
    if glucose > 200:
        glucose_risk = 85
    elif glucose > 140:
        glucose_risk = 60
    else:
        glucose_risk = 30
    risk_factors.append({'name': 'Glucose Level', 'value': glucose_risk, 'color': '#9966ff'})
    
    # Smoking
    smoking = patient.get('smoking_status', '')
    smoking_risk = 0
    if smoking == 'smokes':
        smoking_risk = 80
    elif smoking == 'formerly smoked':
        smoking_risk = 50
    else:
        smoking_risk = 20
    risk_factors.append({'name': 'Smoking', 'value': smoking_risk, 'color': '#ff9f40'})
    
    return risk_factors

def prepare_features(patient):
    """Prepare patient features for ML model"""
    # This should match your model's expected features
    features = [
        patient.get('age', 0),
        1 if patient.get('gender', '') == 'Male' else 0,
        patient.get('hypertension', 0),
        patient.get('heart_disease', 0),
        1 if patient.get('ever_married', '') == 'Yes' else 0,
        patient.get('avg_glucose_level', 0),
        patient.get('bmi', 0),
        1 if patient.get('smoking_status', '') == 'smokes' else 0
    ]
    return features

@doctor_bp.route('/patients')
@login_required
@doctor_required
def patients():
    """View all patients"""
    try:
        patients = list(mongo.db.patients.find()) if mongo.db is not None else []
        
        for patient in patients:
            if 'user_id' in patient:
                user = User.query.get(patient['user_id'])
                patient['user'] = user
    except Exception as e:
        print(f"Error loading patients: {str(e)}")
        patients = []
    
    return render_template('doctor/patients.html', patients=patients)

@doctor_bp.route('/appointments')
@login_required
@doctor_required
def appointments():
    """View doctor's appointments"""
    try:
        appointments = list(mongo.db.appointments.find({'doctor_id': current_user.id}).sort('date', -1)) if mongo.db is not None else []
        
        for appointment in appointments:
            if 'patient_id' in appointment:
                patient = mongo.db.patients.find_one({'_id': ObjectId(appointment['patient_id'])})
                if patient and 'user_id' in patient:
                    appointment['patient_user'] = User.query.get(patient['user_id'])
    except Exception as e:
        print(f"Error loading appointments: {str(e)}")
        appointments = []
    
    return render_template('doctor/appointments.html', appointments=appointments)