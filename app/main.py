from app.db.database import Base, engine

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api.routes import logs, alerts, analytics
from app.api.routes import ws      
from app.api.routes import health  

from apscheduler.schedulers.background import BackgroundScheduler
from app.ml.ml_runner import run_ml_detection
from app.ml.trainer import train_model
from app.db.database import SessionLocal

from app.models import log, alerts as alerts_model  
from app.models import training_log          

from pathlib import Path        

BASE_DIR = Path(__file__).parent

Base.metadata.create_all(bind=engine)

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
app.include_router(ws.router)    
app.include_router(health.router)  


@app.get("/dashboard")
async def dashboard():
    return FileResponse(BASE_DIR / "frontend" / "dashboard.html", media_type="text/html")


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

scheduler.add_job(training_job, "cron", hour=2, minute=0)

scheduler.add_job(inference_job, "interval", minutes=10)

scheduler.start()