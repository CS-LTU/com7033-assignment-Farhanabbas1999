# Security Integration Guide
## How to Integrate Security Features into Existing Flask Stroke App

This guide shows how to **safely integrate** the new security features without breaking existing functionality.

---

## ⚠️ IMPORTANT: Non-Destructive Integration

All security features are in **separate modules** in `app/security/`. They **do NOT automatically replace** existing code. You choose what to integrate and when.

---

## Step-by-Step Integration

### Step 1: Install Required Dependencies

```bash
# Activate virtual environment
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install security packages
pip install bleach cryptography pytest
pip freeze > requirements.txt
```

---

### Step 2: Enhanced Password Validation (Optional - Gradual)

**Current:** Passwords must be 6+ characters  
**Enhanced:** Strong password policy (8+ chars, uppercase, lowercase, number, special char)

**Option A: Keep existing for current users, enforce for new users**

Update `app/auth/routes.py` registration only:

```python
from app.security import InputValidator

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # ... existing code ...
        
        # ADD: Strong password validation for NEW users
        password = request.form.get('password')
        is_valid, msg = InputValidator.validate_password(password)
        if not is_valid:
            flash(msg, 'danger')
            return redirect(url_for('auth.register'))
        
        # ... rest of existing code ...
```

**Option B: Full replacement (requires user password resets)**

Replace password check in both login and registration routes.

---

### Step 3: Add Rate Limiting to Login (RECOMMENDED)

**Prevents brute force attacks without changing existing logic.**

Update `app/auth/routes.py`:

```python
from app.security import rate_limit

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=5, window_minutes=15, block_minutes=30)  # ADD THIS LINE
def login():
    # Existing login code unchanged
    # ...
```

**That's it!** Rate limiting now active. Test with 6 failed logins to see blocking.

---

### Step 4: Add Audit Logging (RECOMMENDED)

**Logs security events to separate database (audit_logs.db).**

Update `app/auth/routes.py` with logging:

```python
from app.security import AuditLogger

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            # ADD: Log failed login
            AuditLogger.log_from_request(
                AuditLogger.LOGIN_FAILURE,
                f"Failed login attempt for {username}",
                success='failure',
                severity=AuditLogger.WARNING
            )
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('auth.login'))
        
        # ADD: Log successful login
        AuditLogger.log_from_request(
            AuditLogger.LOGIN_SUCCESS,
            f"User {username} logged in successfully",
            current_user=user,
            success='success'
        )
        
        login_user(user)
        # ... rest of code ...
```

**Add logout logging:**

```python
@auth_bp.route('/logout')
@login_required
def logout():
    # ADD: Log logout
    AuditLogger.log_from_request(
        AuditLogger.LOGOUT,
        f"User {current_user.username} logged out",
        current_user=current_user
    )
    
    logout_user()
    # ... rest of code ...
```

---

### Step 5: Input Sanitization in Templates

**Prevents XSS attacks by escaping user input.**

Jinja2 auto-escapes by default, but for extra safety, sanitize before storing:

**Example in doctor/routes.py when creating appointments:**

```python
from app.security import sanitize_input

@doctor_bp.route('/appointments/create', methods=['POST'])
def create_appointment():
    reason = sanitize_input(request.form.get('reason'))  # ADD sanitization
    # ... rest of code ...
```

**For rich text fields (if any):**

```python
description = sanitize_input(request.form.get('description'), allow_html=True)
```

---

### Step 6: Encrypt Sensitive Health Data (OPTIONAL)

**Encrypts BMI, glucose levels, etc. in database.**

**⚠️ REQUIRES DATABASE SCHEMA CHANGES - Test in separate DB first!**

**Example: Encrypt prediction data**

Create new model `app/models_encrypted.py`:

```python
from app import db
from app.security import encrypt_sensitive_data, decrypt_sensitive_data

class EncryptedPrediction(db.Model):
    __tablename__ = 'encrypted_predictions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Store encrypted values
    age_encrypted = db.Column(db.Text)
    bmi_encrypted = db.Column(db.Text)
    glucose_encrypted = db.Column(db.Text)
    
    @property
    def age(self):
        return float(decrypt_sensitive_data(self.age_encrypted))
    
    @age.setter
    def age(self, value):
        self.age_encrypted = encrypt_sensitive_data(str(value))
    
    # Similar for bmi, glucose...
```

**Use in routes:**

```python
pred = EncryptedPrediction(user_id=user.id)
pred.age = 45  # Automatically encrypted
pred.bmi = 28.5
pred.glucose = 110.0
db.session.add(pred)
db.session.commit()

# Reading
patient_age = pred.age  # Automatically decrypted
```

---

### Step 7: Add Security Headers (EASY)

**Update `app/__init__.py`:**

```python
def create_app(config_class=Config):
    app = Flask(__name__)
    # ... existing setup ...
    
    # ADD: Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Only in production with HTTPS
        if not app.config['DEBUG']:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        
        return response
    
    return app
```

---

### Step 8: Update Production Config

**Update `config.py`:**

```python
import os

class ProductionConfig(Config):
    # Must set these environment variables
    SECRET_KEY = os.environ.get('SECRET_KEY')
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    # Secure cookies (HTTPS only)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    DEBUG = False
```

---

## Gradual Rollout Plan

### Phase 1: Non-Intrusive (Week 1)
✅ Install dependencies  
✅ Add rate limiting to login  
✅ Add audit logging to auth routes  
✅ Add security headers  
✅ Run security tests  

**No database changes, no user impact**

### Phase 2: Input Validation (Week 2)
✅ Add input sanitization to forms  
✅ Add file upload validation  
✅ Enhanced validation for new registrations  

**Existing users unaffected**

### Phase 3: Encryption (Week 3+)
⚠️ Test in separate database  
⚠️ Create migration script  
⚠️ Backup production data  
⚠️ Implement encryption for new data  
⚠️ Migrate existing data (optional)  

**Requires careful planning**

---

## Testing Security Features

### 1. Test Rate Limiting

```bash
# Try 6 failed logins
curl -X POST http://localhost:5000/auth/login \
  -d "username=test&password=wrong" \
  --cookie-jar cookies.txt

# Should get blocked after 5 attempts
```

### 2. Test Audit Logging

```python
# Open Python shell
python

from app.security.audit_logger import AuditLogger

# View recent logs
logs = AuditLogger.get_logs(limit=10)
for log in logs:
    print(f"{log.timestamp} - {log.event_type}: {log.description}")

# View failed logins
failed = AuditLogger.get_failed_logins(hours=1)
print(f"Failed logins: {len(failed)}")
```

### 3. Test Password Validation

```python
from app.security import InputValidator

passwords = [
    "weak",              # Too short
    "Weak123",           # No special char
    "Strong@123",        # Valid
    "VeryStr0ng!Pass"    # Valid
]

for pwd in passwords:
    is_valid, msg = InputValidator.validate_password(pwd)
    print(f"{pwd}: {msg}")
```

### 4. Run Test Suite

```bash
pip install pytest
python -m pytest tests/test_security.py -v
```

---

## Viewing Audit Logs

### Via Python

```python
from app.security.audit_logger import AuditLogger

# Last 50 events
logs = AuditLogger.get_logs(limit=50)

# Failed logins in last 24 hours
failed = AuditLogger.get_failed_logins(hours=24)

# Specific user activity
user_logs = AuditLogger.get_logs(username='admin', limit=100)

# Critical events
critical = AuditLogger.get_logs(severity=AuditLogger.CRITICAL)
```

### Via SQLite Browser

1. Download [DB Browser for SQLite](https://sqlitebrowser.org/)
2. Open `audit_logs.db`
3. Browse `audit_logs` table
4. Filter by date, user, event type

### Create Admin Dashboard (Optional)

Create `app/admin/routes.py` audit log viewer:

```python
@admin_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    from app.security.audit_logger import AuditLogger
    
    page = request.args.get('page', 1, type=int)
    event_type = request.args.get('event_type')
    username = request.args.get('username')
    
    logs = AuditLogger.get_logs(
        limit=100,
        event_type=event_type,
        username=username
    )
    
    return render_template('admin/audit_logs.html', logs=logs)
```

---

## Security Checklist for Assignment

### Required Security Features ✅

- [x] **Input Validation** - `InputValidator` class with comprehensive validators
- [x] **SQL Injection Protection** - Using SQLAlchemy ORM (already implemented)
- [x] **XSS Protection** - `sanitize_input()` function using bleach
- [x] **Session Security** - HTTPOnly, SameSite cookies configured
- [x] **Password Policies** - Strong password validation (8+ chars, mixed case, numbers, special)
- [x] **Audit Logging** - Separate database with all security events
- [x] **Rate Limiting** - Brute force protection on login
- [x] **Data Encryption** - Fernet encryption for sensitive health data
- [x] **CSRF Protection** - Flask-WTF (already enabled)

### Documentation ✅

- [x] **Security Documentation** - `docs/SECURITY.md` (comprehensive)
- [x] **Integration Guide** - This file
- [x] **API Documentation** - Included in security docs
- [x] **Deployment Guide** - Production security in `docs/SECURITY.md`

### Testing ✅

- [x] **Unit Tests** - `tests/test_security.py` with pytest
- [x] **Security Testing** - Test cases for all validators, encryption, rate limiting
- [x] **Manual Testing Checklist** - In security documentation

### Compliance Considerations ✅

- [x] **Data Privacy** - GDPR considerations documented
- [x] **Healthcare Compliance** - HIPAA safeguards documented
- [x] **Data Retention** - Policy documented
- [x] **Audit Trail** - Separate audit database

---

## Troubleshooting

### Issue: "Module 'app.security' not found"

**Solution:** Make sure `__init__.py` exists in `app/security/`:

```bash
# Check file exists
ls app/security/__init__.py

# If missing, create it
echo "from .validators import *" > app/security/__init__.py
```

### Issue: "cryptography module not found"

**Solution:**

```bash
pip install cryptography
```

### Issue: Rate limiter not working

**Solution:** Rate limiter is in-memory. Restarting Flask clears limits. For persistent rate limiting, integrate Redis:

```bash
pip install redis flask-limiter
```

### Issue: Audit logs not showing

**Solution:**

```python
# Check if database file exists
import os
print(os.path.exists('audit_logs.db'))

# Manually create table
from app.security.audit_logger import AuditBase, audit_engine
AuditBase.metadata.create_all(audit_engine)

# Test logging
from app.security import AuditLogger
AuditLogger.log_event(
    AuditLogger.LOGIN_SUCCESS,
    "Test event",
    username="test"
)
```

---

## Performance Considerations

### Rate Limiter Memory Usage

In-memory rate limiter stores attempts in Python dict. For high-traffic:

**Cleanup job:**
```python
from app.security import get_rate_limiter

# In Flask before_request or scheduled job
@app.before_request
def cleanup_rate_limiter():
    if random.random() < 0.01:  # 1% of requests
        get_rate_limiter().cleanup_old_entries(hours=24)
```

### Audit Log Growth

Audit logs grow over time. Implement rotation:

```python
# Monthly cron job
def archive_old_logs():
    from datetime import datetime, timedelta
    from app.security.audit_logger import AuditLog, AuditSession
    
    cutoff = datetime.utcnow() - timedelta(days=90)
    session = AuditSession()
    
    # Export to file
    old_logs = session.query(AuditLog).filter(AuditLog.timestamp < cutoff).all()
    with open(f'audit_archive_{datetime.now()}.json', 'w') as f:
        json.dump([log.to_dict() for log in old_logs], f)
    
    # Delete from DB
    session.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
    session.commit()
```

---

## Next Steps

1. **Review `docs/SECURITY.md`** - Comprehensive security documentation
2. **Run security tests** - `pytest tests/test_security.py`
3. **Integrate gradually** - Follow Phase 1, 2, 3 above
4. **Test thoroughly** - Manual testing checklist in security docs
5. **Document any customizations** - Keep security docs updated

---

**Questions?** Review `docs/SECURITY.md` or check security module docstrings.

**Security Issues?** Test in development environment first, never in production!
