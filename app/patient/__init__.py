from flask import Blueprint

patient_bp = Blueprint('patient', __name__, url_prefix='/patient')

from app.patient import routes