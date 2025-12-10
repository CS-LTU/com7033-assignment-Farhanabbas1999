from app import create_app, db
from app.models import User, Role, Appointment, Prediction

app = create_app()

with app.app_context():
    print("\n" + "="*60)
    print("DATABASE STATUS CHECK")
    print("="*60)
    
    # Check Roles
    print("\n📋 ROLES:")
    roles = Role.query.all()
    for role in roles:
        print(f"  ✓ {role.name} (ID: {role.id})")
    
    # Check Users by Role
    print("\n👥 USERS:")
    for role in roles:
        users = User.query.filter_by(role_id=role.id).all()
        print(f"\n  {role.name.upper()}s ({len(users)} users):")
        for user in users:
            status = "✅ Active" if user.is_active else "❌ Inactive"
            print(f"    - {user.username} ({user.email}) - {status}")
    
    # Check Appointments
    print("\n📅 APPOINTMENTS:")
    appointments = Appointment.query.all()
    print(f"  Total: {len(appointments)}")
    if appointments:
        for apt in appointments[:5]:  # Show first 5
            print(f"    - ID {apt.id}: {apt.date} {apt.time} - Status: {apt.status}")
    
    # Check Predictions
    print("\n🔮 PREDICTIONS:")
    predictions = Prediction.query.all()
    print(f"  Total: {len(predictions)}")
    if predictions:
        for pred in predictions[:5]:  # Show first 5
            risk = "HIGH RISK" if pred.prediction == 1 else "Low Risk"
            print(f"    - ID {pred.id}: {risk} (User ID: {pred.user_id})")
    
    print("\n" + "="*60)
    print("DATABASE FILE LOCATION:")
    print("="*60)
    import os
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    print(f"  {db_path}")
    print(f"  Exists: {os.path.exists(db_path)}")
    if os.path.exists(db_path):
        size = os.path.getsize(db_path)
        print(f"  Size: {size:,} bytes")
    
    print("\n" + "="*60)
