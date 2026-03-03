from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from datetime import datetime

from app.schemas.log_schema import (
    LogCreate, LogResponse
)

from app.services.log_service import (
    create_log_service,
    get_logs
)

from app.db.database import get_db
from app.core.enums import LogLevel



router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/", response_model=LogResponse)
def create_log(
        log : LogCreate,
        db : Session = Depends(get_db)
    ):
    return create_log_service(db, log)



@router.get("/", response_model=list[LogResponse])
def get_all_logs(
        service : str | None = None,
        level : LogLevel | None = None,
        ip_address : str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit : int = 100,
        offset : int = 0,
        db : Session = Depends(get_db)
    ):
    return get_logs(service, level, ip_address, db, limit, offset, start_time, end_time)
