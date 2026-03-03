from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session


from app.schemas.log_schema import (
    LogCreate, LogResponse
)

from app.services.log_service import (
    create_log_service,
    get_logs_service
)

from app.db.database import get_db



router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/insert-log", response_model=LogResponse)
def create_log(
        log : LogCreate,
        db : Session = Depends(get_db)
    ):
    return create_log_service(db, log)



@router.get("/", response_model=list[LogResponse])
def get_all_logs(db : Session = Depends(get_db)):
    return get_logs_service(db)