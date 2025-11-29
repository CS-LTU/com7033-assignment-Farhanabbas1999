from flask import Flask
from flask_wtf import CSRFProtect

csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)   
    app.config['SECRET_KEY'] = 'Farhan12'

    csrf.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)

    return app