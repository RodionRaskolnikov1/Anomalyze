from sqlalchemy.orm import Session

from app.models.log import Log
from app.schemas.log_schema import LogCreate

from app.services.detection_service import (
    detect_bruteforce
)

from app.services.event_normalizer import normalize_event

def create_log_service(db : Session, log : LogCreate):
    
    try:
        
        normalized_event = normalize_event(log.event_type)
        
        db_log = Log(
            service = log.service,
            event_type = normalized_event,
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
        
        
        if db_log.event_type == "AUTH_LOGIN_FAILED" and db_log.ip_address:
            detect_bruteforce(db, db_log.ip_address)
        
        return db_log
    
    except Exception:
        db.rollback()
        raise
    
    
def get_logs(service, level, ip_address, db : Session, limit, offset, start_time, end_time):
    
    query = db.query(Log)
    
    if service:
        query = query.filter(Log.service == service)
        
    if level:
        query = query.filter(Log.level == level)
        
    if ip_address:
        query = query.filter(Log.ip_address == ip_address)
        
    if start_time:
        query = query.filter(Log.timestamp >= start_time)

    if end_time:
        query = query.filter(Log.timestamp <= end_time)
    
    return query.order_by(Log.timestamp.desc()).offset(offset).limit(limit).all()

