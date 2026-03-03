from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime
import enum


class LogLevel(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogCreate(BaseModel):
    service: str = Field(..., example="matrimony-backend")
    event_type: str = Field(..., example="FAILED_LOGIN")
    level: LogLevel

    message: Optional[str] = Field(None, example="User entered wrong password")

    actor_id: Optional[str] = None
    ip_address: Optional[str] = None
    request_id: Optional[str] = None

    timestamp: Optional[datetime] = None
    context: Optional[Dict[str, Any]] = None


class LogResponse(BaseModel):
    id: UUID
    service: str
    event_type: str
    level: LogLevel
    message: Optional[str]

    actor_id: Optional[str]
    ip_address: Optional[str]
    request_id: Optional[str]

    timestamp: datetime
    context: Optional[Dict]

    class Config:
        from_attributes = True  # For SQLAlchemy ORM