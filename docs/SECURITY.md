# Security Documentation
## Flask Stroke Prediction Application

**Version:** 1.0  
**Date:** December 2025  
**Classification:** Healthcare Application - Secure Software Development Project

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Input Validation & Sanitization](#input-validation--sanitization)
4. [Data Protection](#data-protection)
5. [Audit Logging](#audit-logging)
6. [Rate Limiting](#rate-limiting)
7. [Session Security](#session-security)
8. [Security Testing](#security-testing)
9. [Deployment Security](#deployment-security)
10. [Compliance](#compliance)

---

## Security Overview

This application implements comprehensive security measures following OWASP Top 10 and healthcare data protection standards (HIPAA/GDPR considerations).

### Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Flask Application                       │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Rate       │  │   Input      │  │   CSRF       │ │
│  │   Limiting   │  │   Validation │  │   Protection │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Audit        │  │ Encryption   │  │ Session      │ │
│  │ Logging      │  │ (at rest)    │  │ Security     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────┐  │
│  │         Secure Data Storage (SQLite)             │  │
│  │   - Main DB: app.db (user, appointment, etc)     │  │
│  │   - Audit DB: audit_logs.db (security events)    │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Key Security Features

✅ **Input Validation** - Comprehensive validation for all user inputs  
✅ **SQL Injection Protection** - SQLAlchemy ORM with parameterized queries  
✅ **XSS Protection** - Input sanitization using `bleach` and `markupsafe`  
✅ **CSRF Protection** - Flask-WTF CSRF tokens on all forms  
✅ **Rate Limiting** - Brute force protection on login endpoints  
✅ **Audit Logging** - Separate database for security event tracking  
✅ **Data Encryption** - Sensitive health data encrypted at rest  
✅ **Session Security** - HTTPOnly, SameSite cookies with timeouts  
✅ **Password Policy** - Strong password requirements enforced  
✅ **Role-Based Access Control** - Admin, Doctor, Nurse, Patient roles  

---

## Authentication & Authorization

### Password Policy

Strong passwords are **required** with the following criteria:

- ✅ Minimum 8 characters
- ✅ At least one uppercase letter (A-Z)
- ✅ At least one lowercase letter (a-z)
- ✅ At least one number (0-9)
- ✅ At least one special character (!@#$%^&*(),.?":{}|<>)
- ✅ Maximum 128 characters

**Implementation:**
```python
from app.security import InputValidator

is_valid, message = InputValidator.validate_password(password)
if not is_valid:
    flash(message, 'danger')
```

### Password Storage

Passwords are hashed using **Werkzeug's PBKDF2-SHA256** with salt:
- Never stored in plaintext
- Salt is automatically generated per password
- Computationally expensive to crack (brute force protection)

### Role-Based Access Control (RBAC)

Four distinct roles with hierarchical permissions:

| Role    | Permissions |
|---------|-------------|
| Admin   | Full system access, user management, analytics, reports |
| Doctor  | Patient management, appointments, predictions, analytics |
| Nurse   | Patient vitals, appointment viewing, patient records |
| Patient | View own data, book appointments, view predictions |

**Implementation:**
```python
from app.utils import admin_required

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Only accessible to admins
    pass
```

### Session Security

**Configuration** (`config.py`):
```python
PERMANENT_SESSION_LIFETIME = timedelta(hours=24)  # Auto logout after 24h
SESSION_COOKIE_SECURE = True  # HTTPS only (production)
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
```

**Session Timeout:**
- Sessions expire after 24 hours of inactivity
- Users must re-authenticate after expiry
- Session cleared on logout

---

## Input Validation & Sanitization

### Validation Module

Located in `app/security/validators.py`

**Available Validators:**

```python
from app.security import InputValidator

# Username: alphanumeric + underscore, 3-30 chars
InputValidator.validate_username(username)

# Email: standard RFC format
InputValidator.validate_email(email)

# Password: strong password rules
InputValidator.validate_password(password)

# Phone: digits, spaces, +, -, ()
InputValidator.validate_phone(phone)

# Name: letters, spaces, hyphens, apostrophes
InputValidator.validate_name(name)

# Numeric: with min/max bounds
InputValidator.validate_numeric(value, min_val=0, max_val=100)

# Date: YYYY-MM-DD format
InputValidator.validate_date(date_str)

# Time: HH:MM format
InputValidator.validate_time(time_str)
```

### XSS Prevention

All user inputs are sanitized before display:

```python
from app.security import sanitize_input

# Remove/escape HTML
safe_text = sanitize_input(user_input)

# Allow safe HTML tags (for rich text)
safe_html = sanitize_input(user_input, allow_html=True)
```

**How it works:**
- Uses `bleach` library to clean HTML
- Escapes dangerous characters (`<`, `>`, `&`, `"`, `'`)
- Whitelist-based approach for allowed tags

### File Upload Security

```python
from app.security import validate_file_upload, sanitize_filename

# Validate file
is_valid, error = validate_file_upload(
    file,
    allowed_extensions={'jpg', 'png', 'pdf'},
    max_size_mb=16
)

# Sanitize filename
safe_name = sanitize_filename(file.filename)
```

**Protection:**
- File type validation (whitelist)
- File size limits (16MB max)
- Filename sanitization (prevent path traversal)
- Removes path components (`../`, `..\\`)

---

## Data Protection

### Encryption at Rest

**Module:** `app/security/encryption.py`

Sensitive health data (BMI, glucose levels, medical history) is encrypted using **Fernet (AES-128 CBC)**.

**Usage:**
```python
from app.security import encrypt_sensitive_data, decrypt_sensitive_data

# Encrypt
encrypted_bmi = encrypt_sensitive_data(str(patient_bmi))

# Decrypt
original_bmi = decrypt_sensitive_data(encrypted_bmi)
```

**Key Management:**
- Encryption key derived from secret using PBKDF2
- 100,000 iterations of SHA-256
- Store `ENCRYPTION_KEY` in environment variables

**Production Setup:**
```bash
# Generate a secure key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set environment variable
export ENCRYPTION_KEY="your-generated-key-here"
```

### SQL Injection Protection

**Protection Mechanisms:**
1. **SQLAlchemy ORM** - All queries use parameterized statements
2. **No raw SQL** - Avoid `db.execute()` with user input
3. **Input validation** - All inputs validated before database operations

**Secure Query Examples:**
```python
# ✅ SECURE - Parameterized query
user = User.query.filter_by(username=username).first()

# ✅ SECURE - SQLAlchemy ORM
patients = User.query.filter(User.role_id == patient_role.id).all()

# ❌ INSECURE - Never do this
db.execute(f"SELECT * FROM users WHERE username = '{username}'")
```

---

## Audit Logging

### Separate Audit Database

**Database:** `audit_logs.db` (separate from main application database)

**Purpose:**
- Track all security-relevant events
- Compliance and forensics
- Intrusion detection
- User activity monitoring

### Logged Events

| Event Type | Severity | Description |
|------------|----------|-------------|
| `login_success` | INFO | Successful user login |
| `login_failure` | WARNING | Failed login attempt |
| `logout` | INFO | User logout |
| `register` | INFO | New user registration |
| `password_change` | INFO | Password changed |
| `account_locked` | CRITICAL | Account locked due to attacks |
| `permission_denied` | WARNING | Unauthorized access attempt |
| `data_access` | INFO | Sensitive data accessed |
| `data_create` | INFO | New data created |
| `data_update` | INFO | Data modified |
| `data_delete` | WARNING | Data deleted |
| `rate_limit_exceeded` | WARNING | Rate limit hit |

### Usage

```python
from app.security import AuditLogger

# Log from request context (automatic IP, user agent, etc.)
AuditLogger.log_from_request(
    AuditLogger.LOGIN_SUCCESS,
    f"User {username} logged in successfully",
    current_user=user,
    success='success',
    severity=AuditLogger.INFO
)

# Manual logging
AuditLogger.log_event(
    event_type=AuditLogger.DATA_ACCESS,
    description="Patient record accessed",
    user_id=doctor.id,
    username=doctor.username,
    user_role='doctor',
    ip_address='192.168.1.1',
    severity=AuditLogger.INFO,
    success='success',
    details={'patient_id': patient.id, 'record_type': 'medical_history'}
)
```

### Querying Audit Logs

```python
# Get recent failed logins
failed_logins = AuditLogger.get_failed_logins(username='admin', hours=24)

# Get all logs with filters
logs = AuditLogger.get_logs(
    limit=100,
    event_type=AuditLogger.LOGIN_FAILURE,
    username='suspicious_user',
    ip_address='10.0.0.1',
    severity=AuditLogger.WARNING
)
```

---

## Rate Limiting

### Brute Force Protection

**Module:** `app/security/rate_limiter.py`

Protects against:
- Brute force login attacks
- Password guessing
- Credential stuffing
- DDoS attempts

### Configuration

**Default Limits:**
- **Max Attempts:** 5 failed attempts
- **Time Window:** 15 minutes
- **Block Duration:** 30 minutes

### Implementation

**As Decorator:**
```python
from app.security import rate_limit

@auth_bp.route('/login', methods=['POST'])
@rate_limit(max_attempts=5, window_minutes=15, block_minutes=30)
def login():
    # Login logic
    pass
```

**Manual Usage:**
```python
from app.security import get_rate_limiter, get_client_ip

limiter = get_rate_limiter()
client_ip = get_client_ip()

is_allowed, remaining, wait_time = limiter.record_attempt(
    client_ip,
    max_attempts=5,
    window_minutes=15,
    block_minutes=30
)

if not is_allowed:
    flash(f'Too many attempts. Wait {wait_time // 60} minutes.', 'danger')
    return redirect(url_for('auth.login'))
```

### How It Works

1. **Track Attempts:** Each failed login is recorded with timestamp
2. **Check Window:** Count attempts in rolling time window (15 min)
3. **Block if Exceeded:** Block IP/username for duration (30 min)
4. **Reset on Success:** Successful login clears all attempts
5. **Auto Cleanup:** Old entries automatically removed

### User Experience

**Before Block:**
```
Attempt 1: ❌ "Invalid username or password" (4 remaining)
Attempt 2: ❌ "Invalid username or password" (3 remaining)
...
```

**After Block:**
```
Attempt 6: 🚫 "Too many attempts. Please wait 30 minutes."
```

---

## Session Security

### Session Configuration

**Cookie Security:**
```python
SESSION_COOKIE_SECURE = True       # HTTPS only
SESSION_COOKIE_HTTPONLY = True     # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'    # CSRF protection
```

### Session Timeout

- **Duration:** 24 hours from last activity
- **Auto Logout:** Users logged out after expiry
- **Clear on Logout:** All session data cleared

### CSRF Protection

**Flask-WTF Integration:**
- CSRF tokens auto-generated for all forms
- Tokens validated on POST/PUT/DELETE requests
- Protection against Cross-Site Request Forgery

**Template Usage:**
```html
<form method="POST">
    {{ form.csrf_token }}
    <!-- form fields -->
</form>
```

---

## Security Testing

### Test Suite

**Location:** `tests/test_security.py`

**Run Tests:**
```bash
# Install pytest
pip install pytest

# Run all security tests
python -m pytest tests/test_security.py -v

# Run specific test class
python -m pytest tests/test_security.py::TestInputValidation -v

# Run with coverage
pip install pytest-cov
python -m pytest tests/test_security.py --cov=app.security --cov-report=html
```

### Test Coverage

✅ **Input Validation Tests**
- Username validation (alphanumeric, length)
- Email validation (format, domain)
- Password validation (strength requirements)
- Phone validation (format)
- Name validation (allowed characters)
- Numeric validation (bounds)
- Sanitization (XSS prevention)
- Filename sanitization (path traversal)

✅ **Encryption Tests**
- Encrypt/decrypt cycle
- Null value handling
- Key derivation
- Cross-instance compatibility

✅ **Rate Limiting Tests**
- Allow within limit
- Block after limit
- Reset functionality
- Time window behavior

✅ **Audit Logging Tests**
- Event logging
- Query functionality
- Failed login tracking

### Manual Security Testing Checklist

**Authentication:**
- [ ] Try SQL injection in login (`admin' OR '1'='1`)
- [ ] Try XSS in registration (`<script>alert('xss')</script>`)
- [ ] Attempt brute force (6+ failed logins)
- [ ] Verify session timeout (wait 24+ hours)
- [ ] Check password requirements

**Authorization:**
- [ ] Try accessing admin routes as patient
- [ ] Try accessing other user's data
- [ ] Verify role-based restrictions

**Input Validation:**
- [ ] Submit forms with special characters
- [ ] Try path traversal in file uploads (`../../etc/passwd`)
- [ ] Test maximum input lengths
- [ ] Try negative numbers where only positive allowed

**Session Security:**
- [ ] Check cookies are HTTPOnly (browser DevTools)
- [ ] Verify CSRF tokens are present
- [ ] Try replay attack with old session

---

## Deployment Security

### Production Configuration

**Update `config.py` for production:**

```python
import os

class ProductionConfig:
    # Strong secret key
    SECRET_KEY = os.environ.get('SECRET_KEY')  # Must be set!
    
    # Secure session cookies
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'  # Stronger CSRF
    
    # Database with connection pooling
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Encryption
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')  # Must be set!
    
    # Disable debug
    DEBUG = False
    TESTING = False
```

### Environment Variables

**Required for Production:**

```bash
# Application
export SECRET_KEY="your-very-strong-random-secret-key-here"
export ENCRYPTION_KEY="your-fernet-encryption-key-here"
export FLASK_ENV="production"

# Database
export DATABASE_URL="postgresql://user:pass@localhost/dbname"

# Optional
export SENTRY_DSN="your-sentry-dsn"  # Error tracking
```

**Generate Secure Keys:**

```bash
# Secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### HTTPS/SSL Configuration

**Using Gunicorn + Nginx:**

1. **Install Certbot (Let's Encrypt):**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

2. **Nginx Configuration:**
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

3. **Run with Gunicorn:**
```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 "app:create_app()"
```

### Database Security

**Production Recommendations:**

1. **Use PostgreSQL instead of SQLite:**
```python
SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@localhost/dbname'
```

2. **Restrict Database Access:**
```sql
-- Create limited user
CREATE USER flask_app WITH PASSWORD 'strong_password';
GRANT CONNECT ON DATABASE stroke_app TO flask_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO flask_app;
```

3. **Enable Audit Logging:**
```sql
-- PostgreSQL audit extension
CREATE EXTENSION IF NOT EXISTS pgaudit;
```

4. **Automated Backups:**
```bash
# Cron job for daily backups
0 2 * * * pg_dump stroke_app > /backups/stroke_app_$(date +\%Y\%m\%d).sql
```

### Application Security Headers

**Add to app initialization:**

```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net"
    return response
```

---

## Compliance

### GDPR Considerations

**Data Subject Rights:**
- ✅ Right to access (users can view their data)
- ✅ Right to rectification (users can edit profile)
- ✅ Right to erasure (admin can delete users)
- ✅ Data portability (export functionality needed)

**Implementation:**
```python
# Data export endpoint
@patient_bp.route('/export-data')
@login_required
def export_data():
    data = {
        'user': current_user.to_dict(),
        'appointments': [a.to_dict() for a in current_user.appointments_as_patient],
        'predictions': [p.to_dict() for p in current_user.predictions]
    }
    return jsonify(data)
```

### HIPAA Considerations

**Required Safeguards:**
- ✅ Access Controls (role-based)
- ✅ Audit Controls (audit logging database)
- ✅ Integrity Controls (encryption at rest)
- ✅ Transmission Security (HTTPS/TLS)

**Business Associate Agreement:**
- Required if sharing data with third parties
- Cloud hosting providers must be HIPAA-compliant

### Data Retention Policy

**Recommended Policy:**
```python
# Delete old audit logs after 7 years
def cleanup_old_audit_logs():
    from datetime import datetime, timedelta
    from app.security.audit_logger import AuditLog, AuditSession
    
    cutoff = datetime.utcnow() - timedelta(days=365*7)
    session = AuditSession()
    session.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
    session.commit()
```

---

## Security Incident Response

### Incident Detection

**Monitor audit logs for:**
- Multiple failed login attempts from same IP
- Permission denied events
- Unusual data access patterns
- Rate limit exceeded events

**Automated Alerts:**
```python
# Example: Send email on critical events
def check_for_incidents():
    recent_critical = AuditLogger.get_logs(
        severity=AuditLogger.CRITICAL,
        limit=10
    )
    
    if len(recent_critical) > 5:
        send_alert_email("Multiple critical security events detected")
```

### Response Procedure

1. **Identify:** Review audit logs for event details
2. **Contain:** Block attacker IP, disable compromised accounts
3. **Eradicate:** Remove malicious code, patch vulnerabilities
4. **Recover:** Restore from backups if needed
5. **Learn:** Update security measures, document incident

---

## Contact & Support

**Security Issues:**  
Report vulnerabilities privately to: security@example.com

**Documentation Updates:**  
This document should be reviewed quarterly and updated as security measures evolve.

---

**Last Updated:** December 10, 2025  
**Document Version:** 1.0  
**Classification:** Internal Use
