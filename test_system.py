"""
System Test Script
Tests all database connections and features
"""
from app import create_app, db, mongo
from app.models import User, Role
from datetime import datetime

app = create_app()

with app.app_context():
    print("=" * 60)
    print("SYSTEM TEST")
    print("=" * 60)
    
    # Test 1: SQLite
    print("\n1. Testing SQLite Database...")
    try:
        roles = Role.query.all()
        users = User.query.all()
        print(f"   ✅ SQLite working - {len(roles)} roles, {len(users)} users")
    except Exception as e:
        print(f"   ❌ SQLite error: {e}")
    
    # Test 2: MongoDB
    print("\n2. Testing MongoDB...")
    try:
        mongo.cx.admin.command('ping')
        db_name = mongo.cx.get_database().name
        print(f"   ✅ MongoDB connected - database: {db_name}")
        
        # Count documents
        appointments_count = mongo.db.appointments.count_documents({})
        predictions_count = mongo.db.predictions.count_documents({})
        print(f"   ✅ Appointments: {appointments_count}")
        print(f"   ✅ Predictions: {predictions_count}")
        
    except Exception as e:
        print(f"   ❌ MongoDB error: {e}")
        print("   ⚠️  Start MongoDB with: mongod")
    
    # Test 3: User roles
    print("\n3. Testing User Roles...")
    for role in ['admin', 'doctor', 'nurse', 'patient']:
        count = User.query.join(Role).filter(Role.name == role).count()
        print(f"   {role.capitalize()}: {count} users")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)