import uuid
from sqlalchemy import Column, String, Integer, Float, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.database import Base


class ModelTrainingLog(Base):
    __tablename__ = "model_training_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    trained_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    status = Column(String, nullable=False)  # SUCCESS | SKIPPED | FAILED

    sample_count = Column(Integer, nullable=True)

    feature_count = Column(Integer, nullable=True)

    contamination = Column(Float, nullable=True)
    n_estimators  = Column(Integer, nullable=True)
    training_days = Column(Integer, nullable=True)

    anomalies_on_train_set = Column(Integer, nullable=True)
    anomaly_rate           = Column(Float, nullable=True)   # anomalies / sample_count

    elapsed_seconds = Column(Float, nullable=True)
    notes = Column(Text, nullable=True)