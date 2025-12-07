import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import Role

app = create_app()

with app.app_context():
    # Create roles if they don't exist
    roles = ['patient', 'doctor', 'nurse', 'admin']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name, description=f'{role_name.capitalize()} user'))
    
    db.session.commit()
    print("Roles created successfully!")
    
    # Verify
    all_roles = Role.query.all()
    for r in all_roles:
        print(f"  - {r.name}")