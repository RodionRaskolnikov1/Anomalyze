from fastapi import APIRouter, Depends, Query
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
async def get_all_alerts(
    rule_name:    Optional[str]         = None,
    severity:     Optional[str]         = None,
    ip_address:   Optional[str]         = None,
    actor_id:     Optional[str]         = None,
    alert_status: Optional[AlertStatus] = None,
    limit:  int = Query(default=50, ge=1, le=500,
                        description="Number of alerts to return (max 500)."),
    offset: int = Query(default=0,  ge=0,
                        description="Number of alerts to skip for pagination."),
    db: Session = Depends(get_db),
):
    """
    Paginated alert listing with optional filters.

    Filter examples:
      ?severity=CRITICAL
      ?alert_status=OPEN
      ?ip_address=1.2.3.4&alert_status=OPEN

    Pagination:
      ?limit=50&offset=0   -> page 1
      ?limit=50&offset=50  -> page 2
    """
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
async def patch_alert(
    alert_id: UUID,
    payload:  AlertUpdate,
    db:       Session = Depends(get_db),
):
    """
    Update an alert's lifecycle status and/or notes.

    Examples:
      - Acknowledge:       {"status": "ACKNOWLEDGED"}
      - Resolve with note: {"status": "RESOLVED", "notes": "Blocked at firewall."}
      - False positive:    {"status": "FALSE_POSITIVE", "notes": "Internal load test."}

    Timestamps are set automatically - do not send them.
    """
    return update_alert(db, str(alert_id), payload)