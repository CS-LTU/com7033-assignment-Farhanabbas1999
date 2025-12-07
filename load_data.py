from app import create_app
from app.utils.data_loader import load_stroke_data

app = create_app()
with app.app_context():
    count = load_stroke_data()
    print(f"✅ Loaded {count} records from CSV into MongoDB")