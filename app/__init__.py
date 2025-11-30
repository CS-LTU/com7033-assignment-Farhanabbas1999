from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "main.login"
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)

    # Application Config
    app.config["SECRET_KEY"] = "mysecretkey123"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Initialize Extensions
    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


    from flask_wtf.csrf import generate_csrf
    
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf)
    
    # Register Blueprint
    from .routes import bp
    app.register_blueprint(bp)

    # Create DB tables
    with app.app_context():
        db.create_all()

    return app