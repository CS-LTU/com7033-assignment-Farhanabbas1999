from app.extensions import mongo
import json

def get_stroke_analytics():
    """Get analytics from stroke dataset"""
    stroke_data = list(mongo.db.stroke_data.find())
    
    if not stroke_data:
        return {}
    
    # Stroke cases by gender
    gender_stats = {}
    age_stats = {}
    bmi_stats = {'low': 0, 'normal': 0, 'overweight': 0, 'obese': 0}
    
    for record in stroke_data:
        # Gender analysis
        gender = record.get('gender', 'Unknown')
        stroke = record.get('stroke', 0)
        gender_stats[gender] = gender_stats.get(gender, {'total': 0, 'stroke': 0})
        gender_stats[gender]['total'] += 1
        gender_stats[gender]['stroke'] += int(stroke)
        
        # Age group analysis
        age = record.get('age', 0)
        age_group = f"{int(age//10)*10}-{int(age//10)*10 + 9}"
        age_stats[age_group] = age_stats.get(age_group, {'total': 0, 'stroke': 0})
        age_stats[age_group]['total'] += 1
        age_stats[age_group]['stroke'] += int(stroke)
        
        # BMI analysis
        bmi = record.get('bmi', 0)
        try:
            bmi = float(bmi)
            if bmi < 18.5:
                bmi_stats['low'] += 1
            elif bmi < 25:
                bmi_stats['normal'] += 1
            elif bmi < 30:
                bmi_stats['overweight'] += 1
            else:
                bmi_stats['obese'] += 1
        except:
            pass
    
    return {
        'gender_stats': gender_stats,
        'age_stats': age_stats,
        'bmi_stats': bmi_stats,
        'total_records': len(stroke_data),
        'stroke_cases': sum([r.get('stroke', 0) for r in stroke_data])
    }