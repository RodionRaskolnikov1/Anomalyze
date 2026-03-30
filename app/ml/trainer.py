"""
Trainer
=======
Trains IsolationForest on 30 days of historical log data and
persists the model + scaler to disk via model_store.py.

This runs once daily (scheduled at 2 AM in main.py).
It is deliberately separate from inference — training is expensive
and infrequent; inference is cheap and frequent.

Why 30 days?
  Enough data to capture weekly patterns (weekday vs weekend traffic),
  monthly attack campaigns, and seasonal baseline shifts — without
  being so broad that old behaviour drowns out recent changes.

Why StandardScaler?
  IsolationForest partitions the feature space using random cuts.
  Without scaling, high-magnitude features (request_count in the
  thousands) dominate the cuts and low-magnitude features
  (failed_login_ratio between 0-1) are effectively ignored.
  Scaling puts all features on equal footing.

Minimum sample guard:
  If there are fewer than 100 IP records in the last 30 days,
  the dataset is too small for IsolationForest to learn a meaningful
  baseline. Training is skipped and a warning is logged. The previous
  model (if any) remains on disk and continues to be used for inference.
"""

import logging
import traceback
from datetime import datetime

from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.feature_builder import build_ip_features, FEATURE_COLS
from app.ml.model_store import save_model
from app.models.training_log import ModelTrainingLog

logger = logging.getLogger(__name__)

_MIN_SAMPLES   = 100   # don't train on tiny datasets
_TRAINING_DAYS = 30
_CONTAMINATION = 0.05  # expect ~5% of traffic to be anomalous
_N_ESTIMATORS  = 200   # more trees = more stable anomaly scores


def _write_log(db: Session, **kwargs) -> None:
    """Insert a ModelTrainingLog row. Never raises — audit logging must not crash the trainer."""
    try:
        entry = ModelTrainingLog(**kwargs)
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()
        logger.warning("Failed to write training log entry — continuing anyway.")


def train_model(db: Session) -> bool:
    """
    Full training pipeline:
      1. Build feature matrix from last 30 days of logs
      2. Guard against insufficient data
      3. Fit StandardScaler
      4. Fit IsolationForest on scaled features
      5. Persist model + scaler via model_store
      6. Write audit log entry regardless of outcome

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
            msg = (
                f"Only {len(df)} IP records in last {_TRAINING_DAYS} days "
                f"(minimum is {_MIN_SAMPLES}). Previous model unchanged."
            )
            logger.warning("Training skipped: %s", msg)
            _write_log(
                db,
                status="SKIPPED",
                training_days=_TRAINING_DAYS,
                sample_count=len(df),
                notes=msg,
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
            n_jobs=-1,
        )
        model.fit(X_scaled)

        # ── 5. Persist ────────────────────────────────────────────
        save_model(model, scaler)

        # ── 6. Compute anomaly rate on training set ───────────────
        # Tells us how many IPs the freshly trained model considers anomalous.
        # Should be close to contamination * sample_count.
        # If it drifts far from that expectation, the model needs attention.
        train_preds    = model.predict(X_scaled)
        anomaly_count  = int((train_preds == -1).sum())
        anomaly_rate   = round(anomaly_count / len(df), 4)

        elapsed = (datetime.utcnow() - started_at).total_seconds()

        # ── 7. Write audit log ────────────────────────────────────
        _write_log(
            db,
            status="SUCCESS",
            sample_count=len(df),
            feature_count=len(FEATURE_COLS),
            contamination=_CONTAMINATION,
            n_estimators=_N_ESTIMATORS,
            training_days=_TRAINING_DAYS,
            anomalies_on_train_set=anomaly_count,
            anomaly_rate=anomaly_rate,
            elapsed_seconds=round(elapsed, 2),
        )

        logger.info(
            "=== ML Training Complete | samples=%d | features=%d | "
            "anomaly_rate=%.1f%% | elapsed=%.1fs ===",
            len(df), len(FEATURE_COLS), anomaly_rate * 100, elapsed,
        )
        return True

    except Exception:
        elapsed = (datetime.utcnow() - started_at).total_seconds()
        tb = traceback.format_exc()
        logger.exception("ML training failed with an unexpected error.")
        _write_log(
            db,
            status="FAILED",
            elapsed_seconds=round(elapsed, 2),
            notes=tb[-1000:],   # last 1000 chars of traceback — enough to diagnose
        )
        return False