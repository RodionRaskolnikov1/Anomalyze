from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any


class AlertResponse(BaseModel):
    id: UUID
    rule_name: str
    severity: str

    ip_address: Optional[str]
    actor_id: Optional[str]

    description: Optional[str]

    created_at: datetime

    context: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True