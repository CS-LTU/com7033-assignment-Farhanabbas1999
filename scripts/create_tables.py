import sys
import os

# Add parent directory to path so 'app' can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db

app = create_app()

with app.app_context():
    db.create_all()
    print("Tables created successfully!")
    
    # Verify tables
    inspector = db.inspect(db.engine)
    tables = inspector.get_table_names()
    print(f"Tables in database: {tables}")