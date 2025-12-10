from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.extensions import db
from app.models import User
from datetime import datetime
import os
from werkzeug.utils import secure_filename

from app.profile import profile_bp

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = 'app/static/uploads/profiles'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@profile_bp.route('/')
@login_required
def view_profile():
    """View current user's profile"""
    return render_template('profile/view_profile.html', user=current_user)

@profile_bp.route('/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        try:
            # Update basic info
            current_user.full_name = request.form.get('full_name')
            current_user.phone = request.form.get('phone')
            current_user.address = request.form.get('address')
            current_user.bio = request.form.get('bio')
            current_user.gender = request.form.get('gender')
            
            # Update date of birth
            dob_str = request.form.get('date_of_birth')
            if dob_str:
                try:
                    current_user.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
                except:
                    pass
            
            # Update role-specific fields
            if hasattr(current_user, 'role') and current_user.role:
                if current_user.role.name == 'doctor':
                    current_user.specialization = request.form.get('specialization')
                    current_user.license_number = request.form.get('license_number')
                    current_user.department = request.form.get('department')
                elif current_user.role.name == 'nurse':
                    current_user.license_number = request.form.get('license_number')
                    current_user.department = request.form.get('department')
            
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename and allowed_file(file.filename):
                    # Create upload folder if it doesn't exist
                    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                    
                    # Generate unique filename
                    filename = secure_filename(f"{current_user.id}_{int(datetime.now().timestamp())}_{file.filename}")
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(filepath)
                    
                    # Store relative path
                    current_user.profile_picture = f'uploads/profiles/{filename}'
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile.view_profile'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
    
    return render_template('profile/edit_profile.html', user=current_user)

@profile_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('profile.change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('profile.change_password'))
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('profile.change_password'))
        
        try:
            current_user.set_password(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('profile.view_profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error changing password: {str(e)}', 'danger')
    
    return render_template('profile/change_password.html')

@profile_bp.route('/user/<int:user_id>')
@login_required
def view_user_profile(user_id):
    """View another user's profile (for admins/doctors)"""
    user = User.query.get_or_404(user_id)
    return render_template('profile/view_profile.html', user=user, is_other_user=True)