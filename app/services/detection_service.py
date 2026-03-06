from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.alerts import Alert
from app.models.log import Log


def run_detection_rules(db, log):
    
    if log.ip_address:
        detect_requestflood(db, log.ip_address)
        
    if log.event_type == "AUTH_LOGIN_FAILED" and log.ip_address:
        detect_bruteforce(db, log.ip_address)
        detect_credential_stuffing(db, log.ip_address)
    
    if log.event_type == "PASSWORD_CHANGE" and log.actor_id:
        detect_account_takeover(db, log.actor_id, log.ip_address)

    if log.event_type == "SYSTEM_ERROR":
        detect_system_error_spike(db)



def detect_bruteforce(db : Session, ip_address : str):
    
    now = datetime.utcnow()
    bucket = now.strftime("%Y-%m-%d-%H")
    
    ten_minutes_ago = now - timedelta(minutes=10)
    
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
        
        
        
        
def detect_requestflood(db : Session, ip_address : str):
    try:
        
        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")
        
        window_start = now - timedelta(seconds=60)
        
        request_count = (
            db.query(Log)
            .filter(
                Log.ip_address == ip_address,
                Log.event_type == "API_REQUEST",
                Log.timestamp >= window_start
            )
            .count()
        )
        
        if request_count > 200:
        
            alert_key = f"REQUEST_FLOOD:{ip_address}:{bucket}"
        
            alert = Alert(
                rule_name="REQUEST_FLOOD",
                severity="MEDIUM",
                ip_address=ip_address,
                alert_key=alert_key,
                description="More than 200 requests detected from same IP within 1 minute",
                context={"request flooded": request_count}
            )
            
            db.add(alert)
            db.commit()
        
    except IntegrityError:
        db.rollback()
        


def detect_credential_stuffing(db: Session, ip_address: str):

    try:
        
        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")
        
        window_start = now - timedelta(minutes=5)

        actor_count = (
            db.query(func.count(func.distinct(Log.actor_id)))
            .filter(
                Log.ip_address == ip_address,
                Log.event_type == "AUTH_LOGIN_FAILED",
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if actor_count > 10:

            alert_key = f"CREDENTIAL_STUFFING:{ip_address}:{bucket}"

            alert = Alert(
                rule_name="CREDENTIAL_STUFFING",
                severity="HIGH",
                ip_address=ip_address,
                alert_key=alert_key,
                description="More than 10 unique actor_ids failed login from same IP within 5 minutes",
                context={"unique_actor_count": actor_count}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()
        
        
        
def detect_account_takeover(db: Session, actor_id: str, current_ip: str):

    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")
        
        window_start = now - timedelta(minutes=5)

        login_event = (
            db.query(Log)
            .filter(
                Log.actor_id == actor_id,
                Log.event_type == "AUTH_LOGIN_SUCCESS",
                Log.timestamp >= window_start
            )
            .order_by(Log.timestamp.desc())
            .first()
        )

        if not login_event:
            return

        if login_event.ip_address != current_ip:

            alert_key = f"ACCOUNT_TAKEOVER:{actor_id}:{bucket}"

            alert = Alert(
                rule_name="ACCOUNT_TAKEOVER_SUSPECTED",
                severity="HIGH",
                ip_address=current_ip,
                actor_id=actor_id,
                alert_key=alert_key,
                description="Password change shortly after login from different IP",
                context={
                    "login_ip": login_event.ip_address,
                    "password_change_ip": current_ip
                }
            )

            db.add(alert)
            db.commit()
    
    except IntegrityError:
        db.rollback()


def detect_system_error_spike(db: Session):

    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = datetime.utcnow() - timedelta(minutes=2)

        error_count = (
            db.query(func.count(Log.id))
            .filter(
                Log.event_type == "SYSTEM_ERROR",
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if error_count > 50:

            alert_key = f"SYSTEM_ERROR_SPIKE:{bucket}"

            alert = Alert(
                rule_name="SYSTEM_ERROR_SPIKE",
                severity="MEDIUM",
                alert_key=alert_key,
                description="More than 50 system errors detected within 2 minutes",
                context={"error_count": error_count}
            )

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
