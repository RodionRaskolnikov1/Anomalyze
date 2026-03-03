from sqlalchemy.orm import Session

from app.models.log import Log
from app.schemas.log_schema import LogCreate

def create_log_service(db : Session, log : LogCreate):
    
    try:
        db_log = Log(
            service = log.service,
            event_type = log.event_type,
            level = log.level,
            message = log.message,
            actor_id = log.actor_id,
            ip_address = log.ip_address,
            request_id = log.request_id,
            context = log.context
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        return db_log
    
    except Exception as e:
        db.rollback()
        raise e
    
    

