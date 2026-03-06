from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.schemas.alert_schema import AlertResponse
from app.services.alert_service import get_alerts


router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=list[AlertResponse])
def get_all_alerts(
    rule_name: str | None = None,
    severity: str | None = None,
    ip_address: str | None = None,
    actor_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    return get_alerts(
        db,
        rule_name,
        severity,
        ip_address,
        actor_id,
        limit,
        offset
    )