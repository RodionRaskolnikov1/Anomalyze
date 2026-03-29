from app.db.database import Base, engine, engine1

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    logs, alerts, analytics
)

from apscheduler.schedulers.background import BackgroundScheduler
from app.ml.ml_runner import run_ml_detection
from app.ml.trainer import train_model
from app.db.database import SessionLocal

Base.metadata.create_all(bind=engine1)

app = FastAPI(title="Anomalyze")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  
    allow_methods=["*"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(analytics.router)


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def training_job():
    db = SessionLocal()
    try:
        train_model(db)
    finally:
        db.close()


def inference_job():
    db = SessionLocal()
    try:
        run_ml_detection(db)
    finally:
        db.close()


scheduler = BackgroundScheduler()

# Train once daily at 2 AM — full 30-day window
scheduler.add_job(training_job, "cron", hour=2, minute=0)

# Run inference every 10 minutes — recent window only
scheduler.add_job(inference_job, "interval", minutes=10)

scheduler.start()