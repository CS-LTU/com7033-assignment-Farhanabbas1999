"""
MongoDB Initialization Script
Run this to ensure MongoDB collections exist
"""
from app import create_app, mongo

app = create_app()

with app.app_context():
    try:
        # Check connection
        mongo.cx.admin.command('ping')
        print("✅ MongoDB is running")
        
        # Get database
        db = mongo.cx.get_database()
        print(f"✅ Using database: {db.name}")
        
        # Create collections if they don't exist
        existing_collections = db.list_collection_names()
        
        collections_needed = ['appointments', 'predictions', 'medical_records']
        
        for collection in collections_needed:
            if collection not in existing_collections:
                db.create_collection(collection)
                print(f"✅ Created collection: {collection}")
            else:
                print(f"✅ Collection exists: {collection}")
        
        # Create indexes for better performance
        db.appointments.create_index([('patient_id', 1)])
        db.appointments.create_index([('doctor_id', 1)])
        db.appointments.create_index([('date', -1)])
        db.predictions.create_index([('user_id', 1)])
        db.predictions.create_index([('created_at', -1)])
        
        print("✅ Indexes created successfully")
        print("\n🎉 MongoDB initialization complete!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n⚠️  Make sure MongoDB is running:")
        print("   Windows: net start MongoDB")
        print("   Mac/Linux: sudo systemctl start mongod")
        print("   Or run: mongod")
