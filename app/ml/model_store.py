import logging
from pathlib import Path
from typing import Optional, Tuple

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.core.config import settings

logger = logging.getLogger(__name__)

_MODEL_PATH:  Path = settings.MODELS_DIR / "isolation_forest.pkl"
_SCALER_PATH: Path = settings.MODELS_DIR / "scaler.pkl"


def save_model(model: IsolationForest, scaler: StandardScaler) -> None:
    """Persist model and scaler to disk."""
    joblib.dump(model,  _MODEL_PATH)
    joblib.dump(scaler, _SCALER_PATH)
    logger.info("ML model saved → %s", _MODEL_PATH)
    logger.info("Scaler saved   → %s", _SCALER_PATH)


def load_model() -> Tuple[Optional[IsolationForest], Optional[StandardScaler]]:
    if not _MODEL_PATH.exists() or not _SCALER_PATH.exists():
        logger.warning(
            "No persisted model found at %s. "
            "Run the trainer first (it runs automatically at 2 AM daily, "
            "or call trainer.train_model() manually on first setup).",
            settings.MODELS_DIR,
        )
        return None, None

    model  = joblib.load(_MODEL_PATH)
    scaler = joblib.load(_SCALER_PATH)
    logger.info("ML model and scaler loaded from %s", settings.MODELS_DIR)
    return model, scaler


def model_exists() -> bool:
    """Quick check used by the /health endpoint."""
    return _MODEL_PATH.exists() and _SCALER_PATH.exists()


def model_path() -> Path:
    return _MODEL_PATH