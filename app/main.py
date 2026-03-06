from app.db.database import Base, engine, engine1

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    logs, alerts
)

from apscheduler.schedulers.background import BackgroundScheduler
from app.ml.ml_runner import run_ml_detection
from app.db.database import SessionLocal

Base.metadata.create_all(bind=engine1)

app = FastAPI(title="Log-Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"]
)

app.include_router(logs.router)
app.include_router(alerts.router)


def ml_job():
    db = SessionLocal()
    try:
        run_ml_detection(db)
    finally:
        db.close()

scheduler = BackgroundScheduler()
scheduler.add_job(ml_job, "interval", minutes=5)
scheduler.start()