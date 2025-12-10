from app import create_app, db
from app.models import User, Role

app = create_app()

with app.app_context():
    admin_role = Role.query.filter_by(name='admin').first()
    
    if admin_role:
        print(f"✅ Admin role exists (ID: {admin_role.id})")
        admins = User.query.filter_by(role_id=admin_role.id).all()
        
        if admins:
            print(f"\n📋 Found {len(admins)} admin user(s):")
            for admin in admins:
                print(f"  - Username: {admin.username}")
                print(f"    Email: {admin.email}")
                print(f"    Active: {admin.is_active}")
                print()
        else:
            print("\n⚠️  No admin users found in database!")
            print("\nTo create an admin user, you can either:")
            print("1. Register through /auth/register and select 'admin' role")
            print("2. Run the script below to create a default admin\n")
    else:
        print("❌ Admin role not found!")
