from app import create_app, db
from app.models import User, Role
import sqlite3

app = create_app()

print("\n" + "="*70)
print("MIGRATING USERS FROM instance/site.db TO app.db")
print("="*70)

# Connect to old database
old_db_path = 'instance/site.db'
old_conn = sqlite3.connect(old_db_path)
old_cursor = old_conn.cursor()

with app.app_context():
    # Get all users from old database
    old_cursor.execute("""
        SELECT id, username, email, password_hash, full_name, phone, 
               role_id, is_active, created_at, updated_at
        FROM users
    """)
    old_users = old_cursor.fetchall()
    
    print(f"\n📋 Found {len(old_users)} users in old database")
    print("-" * 70)
    
    migrated = 0
    skipped = 0
    
    for old_user in old_users:
        old_id, username, email, password_hash, full_name, phone, role_id, is_active, created_at, updated_at = old_user
        
        # Check if user already exists in new database
        existing = User.query.filter_by(username=username).first()
        if existing:
            print(f"  ⏭️  Skipped: {username} (already exists)")
            skipped += 1
            continue
        
        # Check if role_id exists in new database
        role = Role.query.get(role_id)
        if not role:
            print(f"  ⚠️  Warning: {username} - Invalid role_id {role_id}, setting to patient (4)")
            role_id = 4  # Default to patient
        
        # Create new user
        new_user = User(
            username=username,
            email=email or f"{username}@migrated.com",
            password_hash=password_hash,
            full_name=full_name,
            phone=phone,
            role_id=role_id,
            is_active=bool(is_active) if is_active is not None else True
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            role_name = Role.query.get(role_id).name if role else "unknown"
            print(f"  ✅ Migrated: {username} ({email or 'no email'}) - Role: {role_name}")
            migrated += 1
        except Exception as e:
            db.session.rollback()
            print(f"  ❌ Failed: {username} - {str(e)}")
    
    print("\n" + "="*70)
    print(f"MIGRATION COMPLETE")
    print("="*70)
    print(f"  ✅ Migrated: {migrated} users")
    print(f"  ⏭️  Skipped: {skipped} users (already existed)")
    print(f"  📊 Total in app.db: {User.query.count()} users")
    print("="*70)
    
    print("\n💡 NOTE: Users migrated with their existing passwords.")
    print("   If passwords don't work, users can register again or contact admin.")
    print("\n")

old_conn.close()
