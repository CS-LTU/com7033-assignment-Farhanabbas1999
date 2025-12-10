# Flask Stroke Prediction App - AI Coding Agent Instructions

## Architecture Overview

This is a **role-based Flask healthcare application** for stroke risk prediction with four user roles: Admin, Doctor, Nurse, and Patient. The app uses **SQLite for all data** (users, appointments, predictions) with Flask-Login for authentication and Flask-WTF for CSRF protection.

### Key Components
- **Blueprint Architecture**: Each role has its own blueprint (`/admin`, `/doctor`, `/nurse`, `/patient`, `/auth`, `/profile`)
- **Role-Based Access Control**: Custom decorators (`@admin_required`, `@doctor_required`, `@nurse_required`) enforce role permissions
- **ML Integration**: Pickled stroke prediction model (`stroke_model.pkl`) loaded at startup in `app/main/routes.py`
- **Database**: Single SQLite database (`app.db`) with SQLAlchemy ORM - roles, users, appointments, and predictions

## Critical Setup & Workflows

### Starting the Application
```bash
python run.py  # Starts Flask on debug mode (localhost:5000)
```

Database tables auto-create on startup (`app/__init__.py:create_app()`). Default roles (admin/doctor/nurse/patient) seed automatically if missing.

### Database Management
- **Schema changes**: Use `update_db.py` for raw SQL ALTER statements (manual column additions)
- **Migrations**: Flask-Migrate configured but manual SQL preferred in this codebase
- **Test connectivity**: `python test_system.py` (note: includes MongoDB tests but MongoDB is disabled)

### Role Initialization Pattern
```python
# Always check roles exist before operations
from app.models import Role
role = Role.query.filter_by(name='patient').first()
if role:
    users = User.query.filter_by(role_id=role.id).all()
```

## Code Conventions

### 1. Blueprint Route Protection
**Every role-specific route uses TWO decorators in this order:**
```python
@doctor_bp.route('/dashboard')
@login_required          # Flask-Login check (always first)
@doctor_required         # Role check (always second)
def dashboard():
```

### 2. Role Decorators Location
- **Defined locally** in each blueprint's `routes.py` (e.g., `app/admin/routes.py`, `app/doctor/routes.py`)
- **Also in** `app/utils.py` (centralized but NOT imported/used - blueprints define their own)
- When adding role checks, define decorator in the same file as routes for consistency

### 3. User-Role Relationships
```python
current_user.role.name  # Access role name ('admin', 'doctor', etc.)
user.role_id            # Foreign key to roles table
Role.users              # Backref to all users with that role
```

### 4. Database Session Pattern
Always wrap DB operations in try-except with explicit rollback:
```python
try:
    db.session.add(obj)
    db.session.commit()
    flash('Success!', 'success')
except Exception as e:
    db.session.rollback()
    flash(f'Error: {e}', 'danger')
```

### 5. ML Model Integration
The stroke prediction model is loaded **once at module level** in `app/main/routes.py`:
```python
with open('stroke_model.pkl', 'rb') as f:
    model = pickle.load(f)
```
If model fails to load, fallback logic calculates basic risk scores. Always save predictions to database with `Prediction` model.

### 6. Template Flash Categories
Use Bootstrap-aligned categories: `'success'`, `'danger'`, `'warning'`, `'info'`

### 7. Appointment Status Values
Hardcoded enum-like strings: `'pending'`, `'confirmed'`, `'cancelled'`, `'completed'`

## Important Files

- `app/__init__.py` - App factory, blueprint registration, role seeding
- `app/models.py` - All SQLAlchemy models (User, Role, Appointment, Prediction)
- `config.py` - Config class (note: `USE_MONGODB = False`, `MONGO_URI = None`)
- `app/utils.py` - Centralized role decorators (not imported by blueprints)
- `app/main/routes.py` - ML model loading and prediction endpoint
- `app/templates/base.html` - Bootstrap 5 base template with gradient navbar

## Common Pitfalls

1. **Don't assume MongoDB is active** - Comments reference MongoDB but `config.py` explicitly disables it
2. **Blueprint decorators are duplicated** - Each blueprint defines its own `@role_required` instead of importing from `app/utils.py`
3. **No model file in repo** - `stroke_model.pkl` must exist at root or prediction uses fallback logic
4. **Session management** - Always call `db.session.rollback()` in except blocks
5. **Date/time stored as strings** - Appointments use `date` (YYYY-MM-DD) and `time` (HH:MM) as VARCHAR, not DateTime

## Security Patterns

- CSRF protection enabled globally via Flask-WTF
- Passwords hashed with Werkzeug's `generate_password_hash()`
- Session cookies: `httponly=True`, `samesite='Lax'`, `secure=False` (set True in production)
- File uploads limited to 16MB (`MAX_CONTENT_LENGTH`)
- User activation controlled via `is_active` boolean flag

## Testing & Debugging

- Run `test_system.py` to verify database and roles (ignores MongoDB errors)
- Check terminal output for emoji-prefixed status: ✅ (success), ⚠️ (warning), ❌ (error)
- Debug mode enabled in `run.py` - hot reload active

## When Adding Features

1. **New role?** Add to `Role` seeding in `app/__init__.py` and create decorator in blueprint
2. **New model?** Add to `app/models.py`, run `db.create_all()` in app context or use `update_db.py` pattern
3. **New blueprint?** Register in `app/__init__.py:create_app()` after imports
4. **Role-specific page?** Always use `@login_required` + `@role_required` decorators
