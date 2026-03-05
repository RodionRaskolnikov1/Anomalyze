from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.alerts import Alert
from app.models.log import Log



def detect_bruteforce(db : Session, ip_address : str):
    
    bucket = datetime.utcnow().strftime("%Y-%m-%d-%H")
    
    ten_minutes_ago = datetime.utcnow() - timedelta(minutes=10)
    
    failed_attempts = (
        db.query(func.count(Log.id))
        .filter(
            Log.ip_address == ip_address,
            Log.event_type == "AUTH_LOGIN_FAILED",
            Log.timestamp >= ten_minutes_ago    
        )
        .scalar()
    )
    
    if failed_attempts >= 5:
        
        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.rule_name == "BRUTE_FORCE_LOGIN",
                Alert.ip_address == ip_address,
                Alert.created_at >= ten_minutes_ago
            )
            .first()
        )

        if existing_alert:
            return
        
        alert_key = f"BRUTE_FORCE_LOGIN:{ip_address}:{bucket}"
        
        alert = Alert(
            rule_name="BRUTE_FORCE_LOGIN",
            severity="HIGH",
            ip_address=ip_address,
            alert_key=alert_key,
            description="Multiple failed login attempts detected",
            context={"attempts": failed_attempts}
        )
        
        try:
            db.add(alert)
            db.commit()
        except IntegrityError:
            db.rollback()
        
        
        
        
'''
1. request flood/possible bot
>200 logs from same IP
within 1 minute

ALERT: 
REQUEST_FLOOD
severity: MEDIUM


2. Suspicious Admin Activity
ADMIN_DELETE_USER
>5 times in 5 minutes

ALERT:
ADMIN_DELETE_USER
>5 times in 5 minutes


3. Credential Stuffing
AUTH_LOGIN_FAILED
same IP
>10 unique actor_id
within 5 minutes

attacker trying many accounts

ALERT:
CREDENTIAL_STUFFING
severity: HIGH


4. Suspicious Account Takeover
LOGIN_SUCCESS
followed by password change
from new IP
within short time

ALERT:
ACCOUNT_TAKEOVER_SUSPECTED
severity: HIGH



5. System Error Spike
SYSTEM_ERROR
>50 occurrences
within 2 minutes

ALERT:
SYSTEM_ERROR_SPIKE
severity: MEDIUM


'''
