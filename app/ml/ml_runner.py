import logging
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ml.feature_builder import build_ip_features
from app.ml.anomaly_detector import run_inference
from app.models.alerts import Alert

logger = logging.getLogger(__name__)

_INFERENCE_WINDOW_MINUTES = 10


def _severity_from_score(anomaly_score: float) -> str:
    if anomaly_score >= 75:
        return "HIGH"
    if anomaly_score >= 40:
        return "MEDIUM"
    return "LOW"


def run_ml_detection(db: Session) -> None:
    """
    Main inference job entry point — called by the scheduler in main.py.
    """
    logger.info("ML inference job started.")

    df = build_ip_features(db, minutes=_INFERENCE_WINDOW_MINUTES)

    if df.empty:
        logger.info("No recent log data — inference skipped.")
        return

    result = run_inference(df)

    anomalies = result[result["is_anomaly"] == True]

    if anomalies.empty:
        logger.info("Inference complete — no anomalies flagged.")
        return

    bucket = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")

    try:
        for _, row in anomalies.iterrows():
            severity = _severity_from_score(row["anomaly_score"])

            alert = Alert(
                rule_name="ML_TRAFFIC_ANOMALY",
                severity=severity,
                ip_address=row["ip_address"],
                alert_key=f"ML_ANOMALY:{row['ip_address']}:{bucket}",
                description=(
                    f"ML model detected abnormal traffic pattern "
                    f"(anomaly score: {row['anomaly_score']}/100)"
                ),
                context={
                    # Continuous score — used by threat_score.py
                    "anomaly_score": row["anomaly_score"],
                    "raw_score":     round(float(row["raw_score"]), 4),
                    # Feature snapshot — shows why the model flagged this IP
                    "request_count":       row["request_count"],
                    "failed_login_ratio":  round(float(row["failed_login_ratio"]), 3),
                    "unique_actors":       int(row["unique_actors"]),
                    "unique_user_agents":  int(row["unique_user_agents"]),
                    "error_rate":          round(float(row["error_rate"]), 3),
                    "requests_per_minute": round(float(row["requests_per_minute"]), 2),
                    "off_hours_ratio":     round(float(row["off_hours_ratio"]), 3),
                    "admin_action_count":  int(row["admin_action_count"]),
                },
            )

            db.add(alert)

        db.commit()
        logger.info("ML inference job complete — %d anomaly alerts written.", len(anomalies))

    except IntegrityError:
        # alert_key unique constraint: this IP was already flagged in this bucket.
        # Normal during backfill or rapid re-runs. Silently skip.
        db.rollback()
        logger.debug("IntegrityError on ML alert insert — duplicate bucket, skipped.")