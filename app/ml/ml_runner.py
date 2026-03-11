from app.ml.feature_builder import build_ip_features
from app.ml.anomaly_detector import detect_anomalies
from app.models.alerts import Alert

def run_ml_detection(db):
    
    df = build_ip_features(db)
    
    result = detect_anomalies(df)
    
    anomalies = result[result["anomaly"] == -1]
    
    for _, row in anomalies.iterrows():

        alert = Alert(
            rule_name="ML_TRAFFIC_ANOMALY",
            severity="MEDIUM",
            ip_address=row["ip_address"],
            alert_key=f"ML_ANOMALY:{row['ip_address']}",
            description="ML detected abnormal traffic pattern",
            context=row.to_dict()
        )

        db.add(alert)

    db.commit()
    
    