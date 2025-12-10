from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from config import Config
import os

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Create upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    print("✅ Using SQLite for all data storage")
    
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Register blueprints
    from app.main.routes import main_bp
    from app.auth.routes import auth_bp
    from app.admin.routes import admin_bp
    from app.doctor.routes import doctor_bp
    from app.nurse.routes import nurse_bp
    from app.patient.routes import patient_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(nurse_bp)
    app.register_blueprint(patient_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        print("✅ SQLite database tables created/verified")
        
        # Initialize roles if they don't exist
        from app.models import Role
        if Role.query.count() == 0:
            roles = [
                Role(name='admin', description='System Administrator'),
                Role(name='doctor', description='Medical Doctor'),
                Role(name='nurse', description='Nurse'),
                Role(name='patient', description='Patient')
            ]
            for role in roles:
                db.session.add(role)
            db.session.commit()
            print("✅ Default roles created")
    
    return app

from app.models import User

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))