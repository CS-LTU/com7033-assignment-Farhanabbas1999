import pandas as pd
from app.extensions import mongo
import os

def load_stroke_data():
    """Load stroke CSV data into MongoDB"""
    csv_path = os.path.join(os.path.dirname(__file__), '../../healthcare-dataset-stroke-data.csv')
    
    df = pd.read_csv(csv_path)
    
    # Insert into MongoDB
    stroke_collection = mongo.db.stroke_data
    stroke_collection.delete_many({})  # Clear existing data
    
    records = df.to_dict('records')
    stroke_collection.insert_many(records)
    
    return len(records)

# Run this once: python -c "from app.utils.data_loader import load_stroke_data; load_stroke_data()"