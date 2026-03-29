from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from uuid import UUID
from typing import Optional

from app.db.database import get_db
from app.schemas.alert_schema import AlertResponse, AlertUpdate
from app.services.alert_service import get_alerts, update_alert
from app.core.security import require_api_key
from app.core.enums import AlertStatus


router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_api_key)],
)


@router.get("/", response_model=list[AlertResponse])
def get_all_alerts(
    rule_name:    Optional[str]         = None,
    severity:     Optional[str]         = None,
    ip_address:   Optional[str]         = None,
    actor_id:     Optional[str]         = None,
    alert_status: Optional[AlertStatus] = None,
    limit:        int                   = 100,
    offset:       int                   = 0,
    db:           Session               = Depends(get_db),
):
    return get_alerts(
        db,
        rule_name=rule_name,
        severity=severity,
        ip_address=ip_address,
        actor_id=actor_id,
        alert_status=alert_status,
        limit=limit,
        offset=offset,
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
def patch_alert(
    alert_id: UUID,
    payload:  AlertUpdate,
    db:       Session = Depends(get_db),
):
    
    return update_alert(db, str(alert_id), payload)