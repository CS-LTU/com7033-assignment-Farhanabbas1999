from app import create_app, db
from app.models import User, Role

app = create_app()

with app.app_context():
    # Get admin role
    admin_role = Role.query.filter_by(name='admin').first()
    
    if not admin_role:
        print("❌ Admin role not found! Run the app first to create roles.")
        exit(1)
    
    # Check if admin already exists
    existing_admin = User.query.filter_by(username='admin').first()
    if existing_admin:
        print("⚠️  Admin user already exists!")
        print(f"Username: {existing_admin.username}")
        print(f"Email: {existing_admin.email}")
        exit(0)
    
    # Create default admin user
    admin_user = User(
        username='admin',
        email='admin@strokeapp.com',
        full_name='System Administrator',
        phone='1234567890',
        role_id=admin_role.id,
        is_active=True
    )
    admin_user.set_password('admin123')  # Default password
    
    try:
        db.session.add(admin_user)
        db.session.commit()
        
        print("✅ Admin user created successfully!")
        print("\n" + "="*50)
        print("LOGIN CREDENTIALS:")
        print("="*50)
        print(f"Username: admin")
        print(f"Password: admin123")
        print("="*50)
        print("\n⚠️  IMPORTANT: Change the password after first login!")
        print(f"Visit: http://localhost:5000/auth/login")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating admin: {e}")
