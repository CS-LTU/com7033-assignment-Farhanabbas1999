from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user
from app.extensions import db, mongo  # <-- add mongo
from app.models import User, Role

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role', 'patient')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('auth.register'))

        role = Role.query.filter_by(name=role_name).first()
        user = User(username=username, email=email, role_id=role.id)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if role_name == 'patient':
            mongo.db.patients.insert_one({
                'user_id': user.id,
                'name': username,
                'email': email,
                'medical_history': [],
                'vitals': [],
                'created_at': __import__('datetime').datetime.utcnow()
            })

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        login_user(user)
        return redirect(url_for(f'{user.role.name}.dashboard'))

    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))