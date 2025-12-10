from app import create_app, db
from app.models import User
from sqlalchemy import text

app = create_app()

with app.app_context():
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN full_name VARCHAR(200);"))
        db.session.commit()
        print("✓ Added full_name column")
    except Exception as e:
        print(f"full_name: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN phone VARCHAR(20);"))
        db.session.commit()
        print("✓ Added phone column")
    except Exception as e:
        print(f"phone: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN address TEXT;"))
        db.session.commit()
        print("✓ Added address column")
    except Exception as e:
        print(f"address: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN date_of_birth DATE;"))
        db.session.commit()
        print("✓ Added date_of_birth column")
    except Exception as e:
        print(f"date_of_birth: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN gender VARCHAR(20);"))
        db.session.commit()
        print("✓ Added gender column")
    except Exception as e:
        print(f"gender: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN profile_picture VARCHAR(200);"))
        db.session.commit()
        print("✓ Added profile_picture column")
    except Exception as e:
        print(f"profile_picture: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN bio TEXT;"))
        db.session.commit()
        print("✓ Added bio column")
    except Exception as e:
        print(f"bio: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN specialization VARCHAR(100);"))
        db.session.commit()
        print("✓ Added specialization column")
    except Exception as e:
        print(f"specialization: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN license_number VARCHAR(50);"))
        db.session.commit()
        print("✓ Added license_number column")
    except Exception as e:
        print(f"license_number: {e}")
        db.session.rollback()
    
    try:
        db.session.execute(text("ALTER TABLE users ADD COLUMN department VARCHAR(100);"))
        db.session.commit()
        print("✓ Added department column")
    except Exception as e:
        print(f"department: {e}")
        db.session.rollback()
    
    # Add the is_approved column to existing database
    try:
        # Try to add the column (SQLite will error if it exists)
        with db.engine.connect() as conn:
            conn.execute(db.text('ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 0'))
            conn.commit()
        print("✓ Added is_approved column to users table")
    except Exception as e:
        print(f"Column might already exist or error: {e}")
    
    # Set all existing users as approved
    try:
        db.session.execute(db.text('UPDATE users SET is_approved = 1'))
        db.session.commit()
        print("✓ Set all existing users as approved")
    except Exception as e:
        print(f"Error updating users: {e}")
    
    print("\n✅ Database update completed!")