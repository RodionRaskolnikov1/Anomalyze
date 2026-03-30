import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.ml.model_store import model_exists, model_path
from app.models.training_log import ModelTrainingLog
from app.core.ws_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """
    System health check. No API key required.

    Returns 200 if the system is operational (even if degraded).
    Returns 503 only if the database is unreachable.
    """

    # ── 1. Database check ─────────────────────────────────────────
    db_healthy = False
    db_error = None
    try:
        db.execute(text("SELECT 1"))
        db_healthy = True
    except Exception as e:
        db_error = str(e)
        logger.error("Health check: database unreachable — %s", e)

    # ── 2. ML model check ─────────────────────────────────────────
    model_loaded = model_exists()
    model_file   = str(model_path()) if model_loaded else None

    # ── 3. Last training run ──────────────────────────────────────
    last_training = None
    last_training_status = None

    if db_healthy:
        try:
            row = (
                db.query(ModelTrainingLog)
                .order_by(ModelTrainingLog.trained_at.desc())
                .first()
            )
            if row:
                last_training        = row.trained_at.isoformat()
                last_training_status = row.status
        except Exception:
            pass  # non-critical, don't fail health check over this

    # ── 4. Build response ─────────────────────────────────────────
    now = datetime.now(timezone.utc)

    payload = {
        "status":    "healthy" if db_healthy else "unhealthy",
        "timestamp": now.isoformat(),
        "checks": {
            "database": {
                "status": "ok" if db_healthy else "error",
                "error":  db_error,
            },
            "ml_model": {
                "status":     "loaded" if model_loaded else "not_trained_yet",
                "model_file": model_file,
                "last_training_at":     last_training,
                "last_training_status": last_training_status,
            },
            "websocket": {
                "active_connections": manager.active_connections,
            },
        },
    }

    # 503 only when the database is completely down
    status_code = 200 if db_healthy else 503
    return JSONResponse(content=payload, status_code=status_code)