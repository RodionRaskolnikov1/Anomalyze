import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.log import Log

def build_ip_features(db : Session):
    
    now = datetime.utcnow()
    
    window_start = now - timedelta(minutes=5)
    
    rows = (
        db.query(
            Log.ip_address,
            func.count(Log.id).label("request_count"),
            func.sum(
                case(
                    (Log.event_type == "AUTH_LOGIN_FAILED", 1),
                    else_=0
                )
            ).label("failed_logins"),
            
            func.count(func.distinct(Log.actor_id)).label("unique_users")
        )
        .filter(Log.timestamp >= window_start)
        .group_by(Log.ip_address)
        .all()
    )
    
    data = []
    
    for r in rows:
        failed_ratio = r.failed_logins / r.request_count if r.request_count > 0 else 0
   
        data.append({
            "ip_address": r.ip_address,
            "request_count": r.request_count,
            "unique_users": r.unique_users,
            "failed_ratio": failed_ratio
        })
        
    
    return pd.DataFrame(data)
    
