from app.db.database import Base, engine, engine1

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import logs, alerts, analytics
from app.api.routes import ws      # WebSocket live alert stream
from app.api.routes import health  # Health check — no auth required

from apscheduler.schedulers.background import BackgroundScheduler
from app.ml.ml_runner import run_ml_detection
from app.ml.trainer import train_model
from app.db.database import SessionLocal

# Import all models so SQLAlchemy includes their tables in Base.metadata.
# Without these imports, create_all() won't know these tables exist.
from app.models import log, alerts as alerts_model  # noqa: F401
from app.models import training_log                  # noqa: F401

Base.metadata.create_all(bind=engine1)

app = FastAPI(title="Anomalyze")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # cannot be True when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(analytics.router)
app.include_router(ws.router)      # WebSocket — no prefix, endpoint is /ws/alerts
app.include_router(health.router)  # Health check — no auth, no prefix


def training_job():
    """
    Daily full retraining on 30 days of data.
    Runs at 2 AM to avoid peak traffic hours.
    """
    db = SessionLocal()
    try:
        train_model(db)
    finally:
        db.close()


def inference_job():
    """
    Frequent inference using the persisted model.
    Runs every 10 minutes on recent data only.
    """
    db = SessionLocal()
    try:
        run_ml_detection(db)
    finally:
        db.close()


scheduler = BackgroundScheduler()

# Train once daily at 2 AM - full 30-day window
scheduler.add_job(training_job, "cron", hour=2, minute=0)

# Run inference every 10 minutes - recent window only
scheduler.add_job(inference_job, "interval", minutes=10)

scheduler.start()