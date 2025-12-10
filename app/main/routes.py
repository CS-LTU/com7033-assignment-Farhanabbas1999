from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.models import User, Prediction
from app import db
import pickle
import numpy as np
from datetime import datetime

main_bp = Blueprint('main', __name__)

# Load the ML model
try:
    with open('stroke_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✅ ML Model loaded successfully")
except Exception as e:
    print(f"⚠️ Warning: Could not load ML model - {e}")
    model = None

@main_bp.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@main_bp.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    """Stroke prediction page"""
    if request.method == 'POST':
        try:
            # Get form data
            gender = request.form.get('gender')
            age = float(request.form.get('age'))
            hypertension = int(request.form.get('hypertension'))
            heart_disease = int(request.form.get('heart_disease'))
            ever_married = request.form.get('ever_married')
            work_type = request.form.get('work_type')
            residence_type = request.form.get('residence_type')
            avg_glucose_level = float(request.form.get('avg_glucose_level'))
            bmi = float(request.form.get('bmi'))
            smoking_status = request.form.get('smoking_status')
            
            # Encode categorical variables
            gender_encoded = 1 if gender == 'Male' else 0
            married_encoded = 1 if ever_married == 'Yes' else 0
            
            work_type_mapping = {'Private': 0, 'Self-employed': 1, 'Govt_job': 2, 'children': 3, 'Never_worked': 4}
            work_type_encoded = work_type_mapping.get(work_type, 0)
            
            residence_encoded = 1 if residence_type == 'Urban' else 0
            
            smoking_mapping = {'formerly smoked': 0, 'never smoked': 1, 'smokes': 2, 'Unknown': 3}
            smoking_encoded = smoking_mapping.get(smoking_status, 3)
            
            # Prepare features
            features = np.array([[
                gender_encoded, age, hypertension, heart_disease, married_encoded,
                work_type_encoded, residence_encoded, avg_glucose_level, bmi, smoking_encoded
            ]])
            
            # Make prediction
            if model is not None:
                prediction = int(model.predict(features)[0])
                probability = float(model.predict_proba(features)[0][1])
            else:
                # Fallback simple logic if model not available
                risk_score = 0
                if age > 60: risk_score += 2
                if hypertension: risk_score += 2
                if heart_disease: risk_score += 2
                if avg_glucose_level > 200: risk_score += 1
                if bmi > 30: risk_score += 1
                
                prediction = 1 if risk_score >= 4 else 0
                probability = min(risk_score * 0.15, 0.95)
            
            # Save prediction to database
            pred_record = Prediction(
                user_id=current_user.id,
                gender=gender,
                age=age,
                hypertension=hypertension,
                heart_disease=heart_disease,
                ever_married=ever_married,
                work_type=work_type,
                residence_type=residence_type,
                avg_glucose_level=avg_glucose_level,
                bmi=bmi,
                smoking_status=smoking_status,
                prediction=prediction,
                probability=probability
            )
            
            db.session.add(pred_record)
            db.session.commit()
            
            result = {
                'prediction': prediction,
                'probability': probability,
                'risk_level': 'High Risk' if prediction == 1 else 'Low Risk',
                'risk_percentage': round(probability * 100, 2)
            }
            
            return render_template('result.html', result=result, form_data=request.form)
            
        except Exception as e:
            print(f"Error making prediction: {e}")
            flash('Error processing prediction. Please check your inputs.', 'danger')
            return redirect(url_for('main.predict'))
    
    return render_template('predict.html')

@main_bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')