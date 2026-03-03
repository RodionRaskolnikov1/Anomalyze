from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session


from app.schemas.log_schema import (
    LogCreate, LogResponse
)

from app.services.log_service import (
    create_log_service
)

from app.db.database import get_db



router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/logs", response_model=LogResponse)
def create_log(
        log : LogCreate,
        db : Session = Depends(get_db)
    ):
    return create_log_service(db, log)