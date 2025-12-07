from flask import Flask
import os
from .extensions import db, login_manager, csrf, migrate, mongo

def create_app():
    app = Flask(__name__, instance_relative_config=True)

    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'site.db')}"
    app.config['MONGO_URI'] = "mongodb://localhost:27017/strokeapp"
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

    from . import models

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    mongo.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register blueprints
    from .auth.routes import auth_bp
    from .admin.routes import admin_bp
    from .doctor.routes import doctor_bp
    from .patient.routes import patient_bp
    from .nurse.routes import nurse_bp
    from .main.routes import main_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(doctor_bp, url_prefix='/doctor')
    app.register_blueprint(patient_bp, url_prefix='/patient')
    app.register_blueprint(nurse_bp, url_prefix='/nurse')
    app.register_blueprint(main_bp)

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app