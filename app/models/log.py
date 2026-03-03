from sqlalchemy import Column, String, DateTime, Enum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func
import uuid
import enum

from app.db.database import Base


class LogLevel(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Log(Base):
    __tablename__ = "logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service = Column(String, index=True, nullable=False)
    event_type = Column(String, index=True, nullable=False)
    level = Column(Enum(LogLevel), index=True, nullable=False)

    message = Column(String, nullable=True)

    actor_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    request_id = Column(String, index=True, nullable=True)

    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    context = Column(JSONB)