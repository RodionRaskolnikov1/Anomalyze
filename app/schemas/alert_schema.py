from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any

from app.core.enums import AlertStatus


class AlertResponse(BaseModel):
    id:          UUID
    rule_name:   str
    severity:    str

    ip_address:  Optional[str]
    actor_id:    Optional[str]

    description: Optional[str]

    status:          AlertStatus
    acknowledged_at: Optional[datetime]
    resolved_at:     Optional[datetime]
    notes:           Optional[str]

    created_at: datetime
    context:    Optional[Dict[str, Any]]

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    notes:  Optional[str]         = None