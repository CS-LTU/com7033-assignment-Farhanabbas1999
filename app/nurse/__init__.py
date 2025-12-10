from flask import Blueprint

nurse_bp = Blueprint('nurse', __name__, url_prefix='/nurse')

from app.nurse import routes