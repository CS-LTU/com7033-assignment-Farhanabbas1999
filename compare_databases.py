import sqlite3
import os

print("\n" + "="*70)
print("DATABASE FILES COMPARISON")
print("="*70)

databases = [
    ('app.db', 'c:/Users/2414414/Desktop/Secure Software Development/flask_strokeapp/app.db'),
    ('instance/site.db', 'c:/Users/2414414/Desktop/Secure Software Development/flask_strokeapp/instance/site.db'),
    ('instance/stroke_app.db', 'c:/Users/2414414/Desktop/Secure Software Development/flask_strokeapp/instance/stroke_app.db'),
]

for db_name, db_path in databases:
    print(f"\n📁 {db_name}")
    print("-" * 70)
    
    if not os.path.exists(db_path):
        print("  ❌ File does not exist")
        continue
    
    size = os.path.getsize(db_path)
    print(f"  Size: {size:,} bytes")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"  Tables: {len(tables)}")
        
        # Check users
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            print(f"  👥 Users: {user_count}")
            
            # Show some user details
            cursor.execute("SELECT username, email FROM users LIMIT 5")
            users = cursor.fetchall()
            for user in users:
                print(f"      - {user[0]} ({user[1]})")
        except:
            print("  👥 Users: No users table")
        
        # Check appointments
        try:
            cursor.execute("SELECT COUNT(*) FROM appointments")
            apt_count = cursor.fetchone()[0]
            print(f"  📅 Appointments: {apt_count}")
        except:
            print("  📅 Appointments: No appointments table")
        
        # Check predictions
        try:
            cursor.execute("SELECT COUNT(*) FROM predictions")
            pred_count = cursor.fetchone()[0]
            print(f"  🔮 Predictions: {pred_count}")
        except:
            print("  🔮 Predictions: No predictions table")
        
        conn.close()
        
    except Exception as e:
        print(f"  ❌ Error reading database: {e}")

print("\n" + "="*70)
print("CURRENT CONFIGURATION:")
print("="*70)
print("The app is currently configured to use: app.db")
print("\nIf your data is in instance/site.db or instance/stroke_app.db,")
print("we can copy it to app.db to restore your data!")
print("="*70 + "\n")
