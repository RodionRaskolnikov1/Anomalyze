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

