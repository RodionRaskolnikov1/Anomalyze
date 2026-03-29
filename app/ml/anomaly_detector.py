import logging
import numpy as np
import pandas as pd

from app.ml.feature_builder import FEATURE_COLS
from app.ml.model_store import load_model

logger = logging.getLogger(__name__)

# decision_function threshold below which we flag an IP as anomalous.
# IsolationForest scores cluster around 0 for normal, go negative for anomalies.
# -0.1 is deliberately conservative — we'd rather catch real threats than
# flood the alert table with noise during inference.
_ANOMALY_THRESHOLD = -0.1


def _normalise_score(raw_score: float) -> float:
    """
    Convert IsolationForest decision_function score to 0-100 intensity.
    Lower raw score = more anomalous = higher intensity.
    Clipped to [-0.5, 0.0] before mapping.
    """
    clipped = max(-0.5, min(0.0, raw_score))
    # -0.5 → 100,  0.0 → 0
    return round((clipped / -0.5) * 100, 1)


def run_inference(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Run anomaly detection on a pre-built feature DataFrame.

    Args:
        feature_df: DataFrame with columns ["ip_address"] + FEATURE_COLS.

    Returns:
        DataFrame with two extra columns added:
          - raw_score:     IsolationForest decision_function output
          - anomaly_score: 0-100 normalised intensity (higher = more anomalous)
          - is_anomaly:    bool flag (True when raw_score < _ANOMALY_THRESHOLD)

        Returns the input unchanged (with is_anomaly=False) if the model
        isn't loaded yet — safe to call before the first training run.
    """
    if feature_df.empty:
        return feature_df

    model, scaler = load_model()

    if model is None:
        logger.warning(
            "Inference skipped: no trained model on disk. "
            "Waiting for the daily training job to run."
        )
        feature_df["raw_score"]     = 0.0
        feature_df["anomaly_score"] = 0.0
        feature_df["is_anomaly"]    = False
        return feature_df

    X = feature_df[FEATURE_COLS].values
    X_scaled = scaler.transform(X)

    # decision_function: lower = more anomalous
    raw_scores = model.decision_function(X_scaled)

    feature_df["raw_score"]     = raw_scores
    feature_df["anomaly_score"] = [_normalise_score(s) for s in raw_scores]
    feature_df["is_anomaly"]    = raw_scores < _ANOMALY_THRESHOLD

    n_flagged = feature_df["is_anomaly"].sum()
    logger.info(
        "Inference complete | IPs scored=%d | anomalies flagged=%d | threshold=%.2f",
        len(feature_df), n_flagged, _ANOMALY_THRESHOLD,
    )

    return feature_df