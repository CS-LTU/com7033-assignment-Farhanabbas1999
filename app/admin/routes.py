from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.extensions import db, mongo, csrf
from app.models import User, Role
from sqlalchemy import text
from functools import wraps
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        if not hasattr(current_user, 'role') or current_user.role.name != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            from flask import abort
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard"""
    try:
        pending_approvals = db.session.execute(text("SELECT COUNT(*) FROM users WHERE is_approved = 0")).scalar()
    except:
        pending_approvals = 0
    
    stats = {
        'total_users': User.query.count(),
        'total_doctors': User.query.join(Role).filter(Role.name == 'doctor').count(),
        'total_patients': User.query.join(Role).filter(Role.name == 'patient').count(),
        'total_nurses': User.query.join(Role).filter(Role.name == 'nurse').count(),
        'pending_approvals': pending_approvals,
        'total_appointments': mongo.db.appointments.count_documents({}) if mongo.db is not None else 0,
        'total_predictions': mongo.db.predictions.count_documents({}) if mongo.db is not None else 0
    }
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_users=recent_users)

@admin_bp.route('/pending-approvals')
@login_required
@admin_required
def pending_approvals():
    """View pending user approvals"""
    try:
        pending_users = User.query.filter_by(is_approved=False).order_by(User.created_at.desc()).all()
    except:
        # If is_approved column doesn't exist, use raw SQL
        pending_users = db.session.execute(
            text("SELECT * FROM users WHERE is_approved = 0 ORDER BY created_at DESC")
        ).fetchall()
    
    return render_template('admin/pending_approvals.html', pending_users=pending_users)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """View all users"""
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=all_users)

@admin_bp.route('/doctors')
@login_required
@admin_required
def doctors():
    """View all doctors"""
    try:
        pending_approvals = db.session.execute(text("SELECT COUNT(*) FROM users WHERE is_approved = 0")).scalar()
    except:
        pending_approvals = 0
    
    stats = {
        'pending_approvals': pending_approvals
    }
    
    doctor_role = Role.query.filter_by(name='doctor').first()
    
    if doctor_role:
        doctors = User.query.filter_by(role_id=doctor_role.id).all()
    else:
        doctors = []
    
    return render_template('admin/doctors.html', doctors=doctors, stats=stats)

@admin_bp.route('/nurses')
@login_required
@admin_required
def nurses():
    """View all nurses"""
    try:
        pending_approvals = db.session.execute(text("SELECT COUNT(*) FROM users WHERE is_approved = 0")).scalar()
    except:
        pending_approvals = 0
    
    stats = {
        'pending_approvals': pending_approvals
    }
    
    nurse_role = Role.query.filter_by(name='nurse').first()
    
    if nurse_role:
        nurses = User.query.filter_by(role_id=nurse_role.id).all()
    else:
        nurses = []
    
    return render_template('admin/nurses.html', nurses=nurses, stats=stats)

@admin_bp.route('/patients')
@login_required
@admin_required
def patients():
    """View all patients"""
    try:
        # Get pending approvals count
        pending_approvals = db.session.execute(text("SELECT COUNT(*) FROM users WHERE is_approved = 0")).scalar()
    except:
        pending_approvals = 0
    
    # Get stats for the template
    stats = {
        'pending_approvals': pending_approvals
    }
    
    # Get patient role
    patient_role = Role.query.filter_by(name='patient').first()
    
    if patient_role:
        patients = User.query.filter_by(role_id=patient_role.id).all()
    else:
        patients = []
    
    return render_template('admin/patients.html', patients=patients, stats=stats)

# Make sure the approve_user route exempts CSRF or the form includes the token

@admin_bp.route('/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt  # Add this if using POST without form
def approve_user(user_id):
    """Approve a user"""
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.execute(text(f"UPDATE users SET is_approved = 1 WHERE id = {user_id}"))
        db.session.commit()
        flash(f'User {user.username} has been approved!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.pending_approvals'))

@admin_bp.route('/reject/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt  # Add this if using POST without form
def reject_user(user_id):
    """Reject a user"""
    user = User.query.get_or_404(user_id)
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been rejected and deleted!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.pending_approvals'))

@admin_bp.route('/toggle-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt  # Add this
def toggle_user_status(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    try:
        user.is_active = not user.is_active
        db.session.commit()
        status = 'activated' if user.is_active else 'deactivated'
        flash(f'User {user.username} has been {status}!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user status: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('admin.users'))

@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """Analytics page with stroke prediction insights"""
    try:
        pending_approvals = db.session.execute(text("SELECT COUNT(*) FROM users WHERE is_approved = 0")).scalar()
    except:
        pending_approvals = 0
    
    stats = {
        'total_patients': mongo.db.patients.count_documents({}) if mongo.db is not None else 0,
        'total_appointments': mongo.db.appointments.count_documents({}) if mongo.db is not None else 0,
        'total_predictions': mongo.db.predictions.count_documents({}) if mongo.db is not None else 0,
        'stroke_positive': mongo.db.predictions.count_documents({'prediction': 1}) if mongo.db is not None else 0,
        'pending_approvals': pending_approvals
    }
    
    try:
        recent_predictions = list(mongo.db.predictions.find().sort('created_at', -1).limit(10)) if mongo.db is not None else []
        
        for pred in recent_predictions:
            if 'user_id' in pred:
                user = User.query.get(pred['user_id'])
                pred['user'] = user
    except Exception as e:
        print(f"Error loading predictions: {str(e)}")
        recent_predictions = []
    
    import pandas as pd
    import os
    import json
    
    try:
        # Try multiple possible paths for the CSV file
        possible_paths = [
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'healthcare-dataset-stroke-data.csv'),
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'app', 'data', 'healthcare-dataset-stroke-data.csv'),
            os.path.join('app', 'data', 'healthcare-dataset-stroke-data.csv'),
            'healthcare-dataset-stroke-data.csv'
        ]
        
        csv_path = None
        for path in possible_paths:
            if os.path.exists(path):
                csv_path = path
                print(f"✅ Found CSV at: {csv_path}")
                break
        
        if not csv_path:
            raise FileNotFoundError(f"CSV file not found. Searched in: {possible_paths}")
        
        df = pd.read_csv(csv_path)
        print(f"✅ Loaded CSV with {len(df)} rows")
        
        # Clean data
        df['bmi'] = pd.to_numeric(df['bmi'], errors='coerce')
        df = df.dropna(subset=['bmi'])
        
        stroke_analytics = {
            'total_records': len(df),
            'stroke_distribution': {
                'stroke': int(df['stroke'].sum()),
                'no_stroke': int((df['stroke'] == 0).sum())
            },
            'gender_distribution': df['gender'].value_counts().to_dict(),
            'hypertension_count': int(df['hypertension'].sum()),
            'heart_disease_count': int(df['heart_disease'].sum()),
        }
        
        # 1. Age vs Stroke - Group by age ranges
        age_bins = [0, 20, 30, 40, 50, 60, 70, 80, 100]
        age_labels = ['0-20', '21-30', '31-40', '41-50', '51-60', '61-70', '71-80', '80+']
        df['age_group'] = pd.cut(df['age'], bins=age_bins, labels=age_labels, right=False)
        
        age_stroke_data = df[df['stroke'] == 1].groupby('age_group').size().reindex(age_labels, fill_value=0)
        stroke_analytics['age_vs_stroke'] = {
            'labels': age_labels,
            'data': age_stroke_data.tolist()
        }
        
        # 2. Gender vs Stroke
        gender_stroke = df[df['stroke'] == 1]['gender'].value_counts().to_dict()
        stroke_analytics['gender_vs_stroke'] = gender_stroke
        
        # 3. Hypertension vs Stroke
        hypertension_stroke = df[df['stroke'] == 1]['hypertension'].value_counts().to_dict()
        hypertension_no_stroke = df[df['stroke'] == 0]['hypertension'].value_counts().to_dict()
        stroke_analytics['hypertension_vs_stroke'] = {
            'with_hypertension_stroke': hypertension_stroke.get(1, 0),
            'without_hypertension_stroke': hypertension_stroke.get(0, 0),
            'with_hypertension_no_stroke': hypertension_no_stroke.get(1, 0),
            'without_hypertension_no_stroke': hypertension_no_stroke.get(0, 0)
        }
        
        # 4. Heart Disease vs Stroke
        heart_stroke = df[df['stroke'] == 1]['heart_disease'].value_counts().to_dict()
        heart_no_stroke = df[df['stroke'] == 0]['heart_disease'].value_counts().to_dict()
        stroke_analytics['heart_disease_vs_stroke'] = {
            'with_heart_disease_stroke': heart_stroke.get(1, 0),
            'without_heart_disease_stroke': heart_stroke.get(0, 0),
            'with_heart_disease_no_stroke': heart_no_stroke.get(1, 0),
            'without_heart_disease_no_stroke': heart_no_stroke.get(0, 0)
        }
        
        # 5. Smoking Status vs Stroke
        if 'smoking_status' in df.columns:
            smoking_stroke = df[df['stroke'] == 1]['smoking_status'].value_counts().to_dict()
            stroke_analytics['smoking_vs_stroke'] = smoking_stroke
        else:
            stroke_analytics['smoking_vs_stroke'] = {}
        
        # 6. BMI vs Stroke (Categories)
        df['bmi_category'] = pd.cut(df['bmi'], 
                                     bins=[0, 18.5, 25, 30, 100], 
                                     labels=['Underweight', 'Normal', 'Overweight', 'Obese'])
        bmi_stroke = df[df['stroke'] == 1]['bmi_category'].value_counts().to_dict()
        stroke_analytics['bmi_vs_stroke'] = {str(k): int(v) for k, v in bmi_stroke.items()}
        
        # 7. Glucose Level vs Stroke (Average)
        glucose_stroke_avg = df[df['stroke'] == 1]['avg_glucose_level'].mean()
        glucose_no_stroke_avg = df[df['stroke'] == 0]['avg_glucose_level'].mean()
        stroke_analytics['glucose_vs_stroke'] = {
            'stroke_avg': round(glucose_stroke_avg, 2),
            'no_stroke_avg': round(glucose_no_stroke_avg, 2)
        }
        
        # Glucose Level Ranges
        glucose_bins = [0, 100, 126, 200, 300]
        glucose_labels = ['Normal (<100)', 'Pre-diabetes (100-125)', 'Diabetes (126-199)', 'High (200+)']
        df['glucose_category'] = pd.cut(df['avg_glucose_level'], bins=glucose_bins, labels=glucose_labels, right=False)
        glucose_stroke = df[df['stroke'] == 1]['glucose_category'].value_counts().reindex(glucose_labels, fill_value=0)
        stroke_analytics['glucose_categories_vs_stroke'] = {
            'labels': glucose_labels,
            'data': glucose_stroke.tolist()
        }
        
        # Convert to JSON for JavaScript
        stroke_analytics_json = json.dumps(stroke_analytics)
        print("✅ Analytics data prepared successfully")
        
    except Exception as e:
        print(f"❌ Error loading stroke analytics: {str(e)}")
        import traceback
        traceback.print_exc()
        
        stroke_analytics = {
            'total_records': 0,
            'stroke_distribution': {'stroke': 0, 'no_stroke': 0},
            'age_vs_stroke': {'labels': [], 'data': []},
            'gender_vs_stroke': {},
            'hypertension_vs_stroke': {
                'with_hypertension_stroke': 0,
                'without_hypertension_stroke': 0,
                'with_hypertension_no_stroke': 0,
                'without_hypertension_no_stroke': 0
            },
            'heart_disease_vs_stroke': {
                'with_heart_disease_stroke': 0,
                'without_heart_disease_stroke': 0,
                'with_heart_disease_no_stroke': 0,
                'without_heart_disease_no_stroke': 0
            },
            'smoking_vs_stroke': {},
            'bmi_vs_stroke': {},
            'glucose_vs_stroke': {'stroke_avg': 0, 'no_stroke_avg': 0},
            'glucose_categories_vs_stroke': {'labels': [], 'data': []}
        }
        stroke_analytics_json = json.dumps(stroke_analytics)
        flash('Unable to load CSV data for analytics. Please ensure the healthcare dataset file is in the correct location.', 'warning')
    
    return render_template('admin/analytics.html',
                         stats=stats,
                         recent_predictions=recent_predictions,
                         stroke_analytics=stroke_analytics,
                         stroke_analytics_json=stroke_analytics_json)

@admin_bp.route('/add-doctor', methods=['GET', 'POST'])
@login_required
@admin_required
def add_doctor():
    """Add a new doctor"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        doctor_role = Role.query.filter_by(name='doctor').first()
        if not doctor_role:
            flash('Doctor role not found', 'danger')
            return redirect(url_for('admin.add_doctor'))
        
        try:
            new_doctor = User(
                username=username,
                email=email,
                role_id=doctor_role.id,
                is_active=True
            )
            new_doctor.set_password(password)
            db.session.add(new_doctor)
            db.session.commit()
            
            db.session.execute(text(f"UPDATE users SET is_approved = 1 WHERE id = {new_doctor.id}"))
            db.session.commit()
            
            flash(f'Doctor "{username}" added successfully!', 'success')
            return redirect(url_for('admin.doctors'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding doctor: {str(e)}', 'danger')
    
    return render_template('admin/add_doctor.html')

@admin_bp.route('/add-nurse', methods=['GET', 'POST'])
@login_required
@admin_required
def add_nurse():
    """Add a new nurse"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        nurse_role = Role.query.filter_by(name='nurse').first()
        if not nurse_role:
            flash('Nurse role not found', 'danger')
            return redirect(url_for('admin.add_nurse'))
        
        try:
            new_nurse = User(
                username=username,
                email=email,
                role_id=nurse_role.id,
                is_active=True
            )
            new_nurse.set_password(password)
            db.session.add(new_nurse)
            db.session.commit()
            
            db.session.execute(text(f"UPDATE users SET is_approved = 1 WHERE id = {new_nurse.id}"))
            db.session.commit()
            
            flash(f'Nurse "{username}" added successfully!', 'success')
            return redirect(url_for('admin.nurses'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding nurse: {str(e)}', 'danger')
    
    return render_template('admin/add_nurse.html')

@admin_bp.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit user details"""
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user_id:
            flash('Username already exists', 'danger')
            return redirect(url_for('admin.edit_user', user_id=user_id))
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user_id:
            flash('Email already exists', 'danger')
            return redirect(url_for('admin.edit_user', user_id=user_id))
        
        try:
            user.username = username
            user.email = email
            
            if password:
                if len(password) < 6:
                    flash('Password must be at least 6 characters', 'danger')
                    return redirect(url_for('admin.edit_user', user_id=user_id))
                user.set_password(password)
            
            db.session.commit()
            flash('User updated successfully!', 'success')
            
            if user.role.name == 'doctor':
                return redirect(url_for('admin.doctors'))
            elif user.role.name == 'nurse':
                return redirect(url_for('admin.nurses'))
            else:
                return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')
    
    return render_template('admin/edit_user.html', user=user)

@admin_bp.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def delete_user(user_id):
    """Delete a user"""
    if user_id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin.users'))
    
    user = User.query.get_or_404(user_id)
    username = user.username
    
    try:
        # Delete user from SQLite
        db.session.delete(user)
        db.session.commit()
        
        # Also delete from MongoDB if exists
        if mongo.db is not None:
            mongo.db.patients.delete_many({'user_id': user_id})
            mongo.db.predictions.delete_many({'user_id': user_id})
            mongo.db.appointments.delete_many({'patient_id': user_id})
        
        flash(f'User {username} has been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/appointments')
@login_required
@admin_required
def appointments():
    """View all appointments"""
    try:
        all_appointments = list(mongo.db.appointments.find().sort('created_at', -1)) if mongo.db is not None else []
        
        # Attach user information to each appointment
        for appointment in all_appointments:
            if 'patient_id' in appointment:
                patient = User.query.get(appointment['patient_id'])
                appointment['patient'] = patient
            if 'doctor_id' in appointment:
                doctor = User.query.get(appointment['doctor_id'])
                appointment['doctor'] = doctor
    except Exception as e:
        print(f"Error loading appointments: {str(e)}")
        all_appointments = []
    
    return render_template('admin/appointments.html', appointments=all_appointments)

@admin_bp.route('/manage-admins')
@login_required
@admin_required
def manage_admins():
    """Manage admin users"""
    admin_role = Role.query.filter_by(name='admin').first()
    if admin_role:
        admins = User.query.filter_by(role_id=admin_role.id).all()
    else:
        admins = []
    
    return render_template('admin/manage_admins.html', admins=admins)

@admin_bp.route('/add-admin', methods=['GET', 'POST'])
@login_required
@admin_required
def add_admin():
    """Add a new admin"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            flash('Admin role not found', 'danger')
            return redirect(url_for('admin.add_admin'))
        
        try:
            new_admin = User(
                username=username,
                email=email,
                role_id=admin_role.id,
                is_active=True
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()
            
            db.session.execute(text(f"UPDATE users SET is_approved = 1 WHERE id = {new_admin.id}"))
            db.session.commit()
            
            flash(f'Admin "{username}" added successfully!', 'success')
            return redirect(url_for('admin.manage_admins'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding admin: {str(e)}', 'danger')
    
    return render_template('admin/add_admin.html')

# Add these routes after the manage_admins route

@admin_bp.route('/patient-records')
@login_required
@admin_required
def patient_records():
    """View all patient records from MongoDB"""
    try:
        # Get all patients from MongoDB
        all_patients = list(mongo.db.patients.find().sort('created_at', -1)) if mongo.db is not None else []
        
        # Attach user information
        for patient in all_patients:
            if 'user_id' in patient:
                user = User.query.get(patient['user_id'])
                patient['user'] = user
            
            # Get prediction count for this patient
            if 'user_id' in patient:
                prediction_count = mongo.db.predictions.count_documents({'user_id': patient['user_id']}) if mongo.db is not None else 0
                patient['prediction_count'] = prediction_count
            
            # Get appointment count
            if 'user_id' in patient:
                appointment_count = mongo.db.appointments.count_documents({'patient_id': patient['user_id']}) if mongo.db is not None else 0
                patient['appointment_count'] = appointment_count
    except Exception as e:
        print(f"Error loading patient records: {str(e)}")
        all_patients = []
        flash(f'Error loading patient records: {str(e)}', 'danger')
    
    return render_template('admin/patient_records.html', patients=all_patients)

@admin_bp.route('/patient-record/<patient_id>')
@login_required
@admin_required
def view_patient_record(patient_id):
    """View detailed patient record"""
    try:
        from bson.objectid import ObjectId
        patient = mongo.db.patients.find_one({'_id': ObjectId(patient_id)}) if mongo.db is not None else None
        
        if not patient:
            flash('Patient record not found', 'danger')
            return redirect(url_for('admin.patient_records'))
        
        # Get user information
        if 'user_id' in patient:
            user = User.query.get(patient['user_id'])
            patient['user'] = user
        
        # Get all predictions for this patient
        predictions = list(mongo.db.predictions.find({'user_id': patient.get('user_id')}).sort('created_at', -1)) if mongo.db is not None else []
        
        # Get all appointments for this patient
        appointments = list(mongo.db.appointments.find({'patient_id': patient.get('user_id')}).sort('created_at', -1)) if mongo.db is not None else []
        
        # Attach doctor info to appointments
        for appointment in appointments:
            if 'doctor_id' in appointment:
                doctor = User.query.get(appointment['doctor_id'])
                appointment['doctor'] = doctor
        
    except Exception as e:
        print(f"Error loading patient record: {str(e)}")
        flash(f'Error loading patient record: {str(e)}', 'danger')
        return redirect(url_for('admin.patient_records'))
    
    return render_template('admin/view_patient_record.html', 
                         patient=patient, 
                         predictions=predictions,
                         appointments=appointments)

@admin_bp.route('/delete-patient-record/<patient_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def delete_patient_record(patient_id):
    """Delete a patient record from MongoDB"""
    try:
        from bson.objectid import ObjectId
        result = mongo.db.patients.delete_one({'_id': ObjectId(patient_id)}) if mongo.db is not None else None
        
        if result and result.deleted_count > 0:
            flash('Patient record deleted successfully!', 'success')
        else:
            flash('Patient record not found', 'warning')
    except Exception as e:
        print(f"Error deleting patient record: {str(e)}")
        flash(f'Error deleting patient record: {str(e)}', 'danger')
    
    return redirect(url_for('admin.patient_records'))

@admin_bp.route('/delete-prediction/<prediction_id>', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def delete_prediction(prediction_id):
    """Delete a prediction record"""
    try:
        from bson.objectid import ObjectId
        result = mongo.db.predictions.delete_one({'_id': ObjectId(prediction_id)}) if mongo.db is not None else None
        
        if result and result.deleted_count > 0:
            flash('Prediction record deleted successfully!', 'success')
        else:
            flash('Prediction record not found', 'warning')
    except Exception as e:
        print(f"Error deleting prediction: {str(e)}")
        flash(f'Error deleting prediction: {str(e)}', 'danger')
    
    return redirect(request.referrer or url_for('admin.patient_records'))

@admin_bp.route('/view-all-predictions')
@login_required
@admin_required
def view_all_predictions():
    """View all predictions made in the system"""
    try:
        all_predictions = list(mongo.db.predictions.find().sort('created_at', -1)) if mongo.db is not None else []
        
        # Attach user information
        for prediction in all_predictions:
            if 'user_id' in prediction:
                user = User.query.get(prediction['user_id'])
                prediction['user'] = user
    except Exception as e:
        print(f"Error loading predictions: {str(e)}")
        all_predictions = []
        flash(f'Error loading predictions: {str(e)}', 'danger')
    
    return render_template('admin/all_predictions.html', predictions=all_predictions)

@admin_bp.route('/doctor-assignments')
@login_required
@admin_required
def doctor_assignments():
    """View all doctor-patient assignments"""
    try:
        # Get all appointments with doctor assignments
        appointments = list(mongo.db.appointments.find({'doctor_id': {'$exists': True}}).sort('created_at', -1)) if mongo.db is not None else []
        
        # Attach user information
        for appointment in appointments:
            if 'patient_id' in appointment:
                patient = User.query.get(appointment['patient_id'])
                appointment['patient'] = patient
            if 'doctor_id' in appointment:
                doctor = User.query.get(appointment['doctor_id'])
                appointment['doctor'] = doctor
    except Exception as e:
        print(f"Error loading doctor assignments: {str(e)}")
        appointments = []
        flash(f'Error loading doctor assignments: {str(e)}', 'danger')
    
    return render_template('admin/doctor_assignments.html', appointments=appointments)