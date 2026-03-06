from app.core.config import settings

from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import create_engine

engine = create_engine(settings.DATABASE_URL)
engine1 = create_engine("sqlite:///./anaomaly.db")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine1)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
