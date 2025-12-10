from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_pymongo import PyMongo
from flask_wtf.csrf import CSRFProtect
import os

db = SQLAlchemy()
login_manager = LoginManager()
mongo = PyMongo()
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stroke_app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # MongoDB configuration
    app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/stroke_app')
    
    # Upload folder
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mongo.init_app(app)
    csrf.init_app(app)
    
    # Login manager settings
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # User loader
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
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
    
    # Create tables and default data
    with app.app_context():
        from app.models import Role, User
        
        db.create_all()
        
        # Create default roles if they don't exist
        roles = ['admin', 'doctor', 'nurse', 'patient']
        for role_name in roles:
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name)
                db.session.add(role)
        
        db.session.commit()
        
        # Create default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin_role = Role.query.filter_by(name='admin').first()
            if admin_role:
                admin = User(
                    username='admin',
                    email='admin@stroke.com',
                    full_name='System Administrator',
                    role_id=admin_role.id,
                    is_active=True,
                    is_approved=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("\n" + "="*50)
                print("✓ Default admin created successfully!")
                print("  Username: admin")
                print("  Password: admin123")
                print("="*50 + "\n")
    
    return app