from app.db.database import Base, engine

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    logs, alerts
)

Base.metadata.create_all(bind=engine)

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