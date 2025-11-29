rom flask import Flask
from flask_wtf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

csrf = CSRFProtect()
db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "main.login"

def create_app():
    app = Flask(_name_)
    app.config['SECRET_KEY'] = 'mysecretkey123'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    csrf.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .routes import bp
    app.register_blueprint(bp)

    with app.app_context():
        db.create_all()

    return app