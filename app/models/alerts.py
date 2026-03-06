from sqlalchemy import Column, String, DateTime, Enum, Index, Text, JSON
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.sql import func
import uuid 

from app.db.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    rule_name = Column(String, index=True, nullable=False)
    severity = Column(String, nullable=False)

    ip_address = Column(String, index=True)
    actor_id = Column(String)
    
    alert_key = Column(String, unique=True, index=True, nullable=False)

    description = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    context = Column(JSON) 