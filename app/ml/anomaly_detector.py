from sklearn.ensemble import IsolationForest

def detect_anomalies(feature_df):
    
    if feature_df.empty:
        return feature_df
    
    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    features = feature_df.drop(columns=["ip_address"])
    
    preds = model.fit_predict(features)
    
    feature_df["anomaly"] = preds

    return feature_df