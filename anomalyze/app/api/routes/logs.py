from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from app.schemas.log_schema import LogCreate, LogResponse
from app.services.log_service import create_log_service, get_logs
from app.db.database import get_db
from app.core.enums import LogLevel
from app.core.security import require_api_key


router = APIRouter(
    prefix="/logs",
    tags=["logs"],
    dependencies=[Depends(require_api_key)],
)


@router.post("/", response_model=LogResponse)
async def create_log(
    log: LogCreate,
    db: Session = Depends(get_db),
):
    return create_log_service(db, log)


@router.get("/", response_model=list[LogResponse])
async def get_all_logs(
    service:    Optional[str]      = None,
    level:      Optional[LogLevel] = None,
    ip_address: Optional[str]      = None,
    start_time: Optional[datetime] = None,
    end_time:   Optional[datetime] = None,
    limit:  int = Query(default=50, ge=1, le=500,
                        description="Number of logs to return (max 500)."),
    offset: int = Query(default=0,  ge=0,
                        description="Number of logs to skip for pagination."),
    db: Session = Depends(get_db),
):
    """
    Paginated log listing.

    Use limit + offset to page through results.
    Example — page 2 at 50 per page: ?limit=50&offset=50

    Hard cap of 500 per request — without this a single
    request on a busy system could return millions of rows.
    """
    return get_logs(service, level, ip_address, db, limit, offset, start_time, end_time)