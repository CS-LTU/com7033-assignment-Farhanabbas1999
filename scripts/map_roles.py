"""
Run this script after you add Role model and add a nullable role_id column.
It will create Role rows (patient, doctor, nurse, admin) and map existing users.
Usage (PowerShell):
$env:FLASK_APP="app:create_app"
python .\scripts\map_roles.py
"""
from app import create_app
from app.extensions import db
from app.models import Role, User

app = create_app()

with app.app_context():
    # create canonical roles if missing
    canonical = ['patient', 'doctor', 'nurse', 'admin']
    for r in canonical:
        if not Role.query.filter_by(name=r).first():
            db.session.add(Role(name=r))
    db.session.commit()

    roles_map = {r.name: r.id for r in Role.query.all()}

    # If old users table has `role` column, map it; otherwise adjust logic
    users = User.query.all()
    for u in users:
        # try to read legacy role attribute
        legacy_role = getattr(u, 'role', None)
        if legacy_role and legacy_role in roles_map:
            u.role_id = roles_map[legacy_role]
    db.session.commit()
    print("Role mapping complete.")