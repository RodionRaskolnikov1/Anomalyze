import logging
from datetime import datetime

from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.feature_builder import build_ip_features, FEATURE_COLS
from app.ml.model_store import save_model

logger = logging.getLogger(__name__)

_MIN_SAMPLES     = 100   # don't train on tiny datasets
_TRAINING_DAYS   = 30
_CONTAMINATION   = 0.05  # expect ~5% of traffic to be anomalous
_N_ESTIMATORS    = 200   # more trees = more stable anomaly scores


def train_model(db: Session) -> bool:
    """
    Full training pipeline:
      1. Build feature matrix from last 30 days of logs
      2. Guard against insufficient data
      3. Fit StandardScaler
      4. Fit IsolationForest on scaled features
      5. Persist model + scaler via model_store

    Returns:
        True  if training succeeded and model was saved.
        False if skipped due to insufficient data or an error.
    """
    logger.info("=== ML Training Job Started ===")
    started_at = datetime.utcnow()

    try:
        # ── 1. Build features ─────────────────────────────────────
        df = build_ip_features(db, days=_TRAINING_DAYS)

        # ── 2. Minimum sample guard ───────────────────────────────
        if len(df) < _MIN_SAMPLES:
            logger.warning(
                "Training skipped: only %d IP records in last %d days "
                "(minimum is %d). Previous model unchanged.",
                len(df), _TRAINING_DAYS, _MIN_SAMPLES,
            )
            return False

        X = df[FEATURE_COLS].values

        # ── 3. Fit scaler ─────────────────────────────────────────
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # ── 4. Fit IsolationForest ────────────────────────────────
        model = IsolationForest(
            n_estimators=_N_ESTIMATORS,
            contamination=_CONTAMINATION,
            random_state=42,
            n_jobs=-1,       # use all CPU cores
        )
        model.fit(X_scaled)

        # ── 5. Persist ────────────────────────────────────────────
        save_model(model, scaler)

        elapsed = (datetime.utcnow() - started_at).total_seconds()
        logger.info(
            "=== ML Training Complete | samples=%d | features=%d | elapsed=%.1fs ===",
            len(df), len(FEATURE_COLS), elapsed,
        )
        return True

    except Exception:
        logger.exception("ML training failed with an unexpected error.")
        return False