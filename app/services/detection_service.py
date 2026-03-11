from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.alerts import Alert
from app.models.log import Log


def run_detection_rules(db, log):

    # --- existing rules ---
    if log.ip_address:
        detect_requestflood(db, log.ip_address)

    if log.event_type == "AUTH_LOGIN_FAILED" and log.ip_address:
        detect_bruteforce(db, log.ip_address)
        detect_credential_stuffing(db, log.ip_address)

    if log.event_type == "PASSWORD_CHANGE" and log.actor_id:
        detect_account_takeover(db, log.actor_id, log.ip_address)

    if log.event_type == "SYSTEM_ERROR":
        detect_system_error_spike(db)

    # --- new rules ---

    # Auth
    if log.event_type == "AUTH_LOGIN_SUCCESS" and log.actor_id:
        detect_impossible_travel(db, log.actor_id, log.ip_address, log.timestamp)

    # Insider / Admin abuse
    if log.event_type in ("ADMIN_DELETE_USER", "ADMIN_BAN_USER",
                          "ADMIN_ROLE_CHANGE", "ADMIN_EXPORT_DATA") and log.actor_id:
        detect_admin_action_burst(db, log.actor_id, log.event_type)

    if log.event_type == "ADMIN_EXPORT_DATA" and log.actor_id:
        detect_data_exfiltration(db, log.actor_id)

    # API abuse / bots
    if log.event_type == "API_REQUEST" and log.ip_address:
        detect_user_agent_rotation(db, log.ip_address)

    if log.event_type in ("API_REQUEST", "API_ERROR") and log.ip_address:
        detect_high_error_rate(db, log.ip_address)

    # Data exfiltration
    if log.event_type in ("RECORD_VIEW", "FILE_DOWNLOAD", "DATA_ACCESS") and log.actor_id:
        detect_bulk_data_access(db, log.actor_id)

    # System health
    if log.event_type == "SERVICE_UNAVAILABLE":
        detect_service_downtime_cascade(db)

    if log.event_type in ("DB_QUERY_SLOW", "DB_CONNECTION_FAILED"):
        detect_database_health_degradation(db)


# ─────────────────────────────────────────────
# EXISTING RULES
# ─────────────────────────────────────────────

def detect_bruteforce(db: Session, ip_address: str):

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


def detect_requestflood(db: Session, ip_address: str):
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
                context={"request_count": request_count}
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

        window_start = now - timedelta(minutes=2)

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


# ─────────────────────────────────────────────
# NEW RULES
# ─────────────────────────────────────────────

# ── AUTH ──────────────────────────────────────

def detect_impossible_travel(db: Session, actor_id: str, current_ip: str, current_time: datetime):
    """
    Impossible Travel
    Trigger : AUTH_LOGIN_SUCCESS from a different IP than the previous login,
              within 10 minutes of the last one.
    Severity: HIGH

    Real attackers often reuse stolen tokens or credentials from a different
    location right after the legitimate user has just logged in.
    A genuine user cannot physically travel between two different IPs in
    under 10 minutes, so this is a strong signal.
    """
    try:

        now = current_time or datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=10)

        previous_login = (
            db.query(Log)
            .filter(
                Log.actor_id == actor_id,
                Log.event_type == "AUTH_LOGIN_SUCCESS",
                Log.ip_address != current_ip,
                Log.timestamp >= window_start,
                Log.timestamp < now
            )
            .order_by(Log.timestamp.desc())
            .first()
        )

        if not previous_login:
            return

        alert_key = f"IMPOSSIBLE_TRAVEL:{actor_id}:{bucket}"

        alert = Alert(
            rule_name="IMPOSSIBLE_TRAVEL",
            severity="HIGH",
            actor_id=actor_id,
            ip_address=current_ip,
            alert_key=alert_key,
            description="Same user logged in from two different IPs within 10 minutes",
            context={
                "previous_ip": previous_login.ip_address,
                "current_ip": current_ip,
                "previous_login_at": str(previous_login.timestamp)
            }
        )

        db.add(alert)
        db.commit()

    except IntegrityError:
        db.rollback()


# ── INSIDER / ADMIN ABUSE ─────────────────────

def detect_admin_action_burst(db: Session, actor_id: str, event_type: str):
    """
    Admin Action Burst
    Trigger : Same admin performs >5 high-impact actions (delete, ban, role change,
              data export) within 5 minutes.
    Severity: HIGH

    Legitimate admins rarely need to delete or modify >5 users in 5 minutes.
    This pattern fits insider threats, compromised admin accounts, or
    scripted abuse of admin privileges.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=5)

        admin_events = [
            "ADMIN_DELETE_USER",
            "ADMIN_BAN_USER",
            "ADMIN_ROLE_CHANGE",
            "ADMIN_EXPORT_DATA"
        ]

        action_count = (
            db.query(func.count(Log.id))
            .filter(
                Log.actor_id == actor_id,
                Log.event_type.in_(admin_events),
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if action_count > 5:

            alert_key = f"ADMIN_ACTION_BURST:{actor_id}:{bucket}"

            alert = Alert(
                rule_name="ADMIN_ACTION_BURST",
                severity="HIGH",
                actor_id=actor_id,
                alert_key=alert_key,
                description="Admin performed more than 5 high-impact actions within 5 minutes",
                context={
                    "action_count": action_count,
                    "triggering_event": event_type
                }
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


def detect_data_exfiltration(db: Session, actor_id: str):
    """
    Admin Data Exfiltration
    Trigger : Same actor triggers ADMIN_EXPORT_DATA more than 3 times in 10 minutes.
    Severity: CRITICAL

    A single export is normal. Multiple exports in quick succession from the
    same actor suggests they are trying to extract as much data as possible
    before access is revoked — a classic insider exfiltration pattern.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=10)

        export_count = (
            db.query(func.count(Log.id))
            .filter(
                Log.actor_id == actor_id,
                Log.event_type == "ADMIN_EXPORT_DATA",
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if export_count > 3:

            alert_key = f"DATA_EXFILTRATION:{actor_id}:{bucket}"

            alert = Alert(
                rule_name="DATA_EXFILTRATION_SUSPECTED",
                severity="CRITICAL",
                actor_id=actor_id,
                alert_key=alert_key,
                description="Actor triggered more than 3 data exports within 10 minutes",
                context={"export_count": export_count}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


# ── API ABUSE / BOTS ──────────────────────────

def detect_user_agent_rotation(db: Session, ip_address: str):
    """
    User-Agent Rotation
    Trigger : Same IP sends requests with >10 distinct user-agent strings
              within 5 minutes.
    Severity: MEDIUM

    Real browsers and apps use a consistent user-agent. Bots and scrapers
    often rotate user-agents to evade per-agent rate limiting.
    Requires user_agent to be stored in log.context e.g. {"user_agent": "..."}.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=5)

        # user_agent is expected in context JSON: {"user_agent": "Mozilla/5.0 ..."}
        logs = (
            db.query(Log.context)
            .filter(
                Log.ip_address == ip_address,
                Log.event_type == "API_REQUEST",
                Log.timestamp >= window_start,
                Log.context.isnot(None)
            )
            .all()
        )

        unique_agents = {
            row.context.get("user_agent")
            for row in logs
            if row.context and row.context.get("user_agent")
        }

        if len(unique_agents) > 10:

            alert_key = f"USER_AGENT_ROTATION:{ip_address}:{bucket}"

            alert = Alert(
                rule_name="USER_AGENT_ROTATION",
                severity="MEDIUM",
                ip_address=ip_address,
                alert_key=alert_key,
                description="More than 10 unique user-agents from same IP within 5 minutes",
                context={"unique_agent_count": len(unique_agents)}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


def detect_high_error_rate(db: Session, ip_address: str):
    """
    High API Error Rate
    Trigger : An IP has an error rate >60% (API_ERROR / total requests)
              over at least 20 requests in the last 5 minutes.
    Severity: MEDIUM

    Normal clients rarely produce sustained high error rates. This pattern
    typically means a bot probing endpoints it doesn't have access to,
    or a scanner fuzzing for vulnerabilities (e.g. 401/403/404 farming).
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=5)

        total = (
            db.query(func.count(Log.id))
            .filter(
                Log.ip_address == ip_address,
                Log.event_type.in_(["API_REQUEST", "API_ERROR"]),
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if total < 20:
            return

        errors = (
            db.query(func.count(Log.id))
            .filter(
                Log.ip_address == ip_address,
                Log.event_type == "API_ERROR",
                Log.timestamp >= window_start
            )
            .scalar()
        )

        error_rate = errors / total

        if error_rate > 0.6:

            alert_key = f"HIGH_ERROR_RATE:{ip_address}:{bucket}"

            alert = Alert(
                rule_name="HIGH_API_ERROR_RATE",
                severity="MEDIUM",
                ip_address=ip_address,
                alert_key=alert_key,
                description="IP has more than 60% API error rate over last 5 minutes",
                context={
                    "total_requests": total,
                    "error_count": errors,
                    "error_rate_pct": round(error_rate * 100, 1)
                }
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


# ── DATA EXFILTRATION ─────────────────────────

def detect_bulk_data_access(db: Session, actor_id: str):
    """
    Bulk Data Access
    Trigger : A single actor accesses >100 distinct records (RECORD_VIEW,
              FILE_DOWNLOAD, DATA_ACCESS) within 10 minutes.
    Severity: HIGH

    Normal users browse a handful of records at a time. Bulk access in a
    short window suggests automated scraping, a compromised account being
    used to harvest data, or a malicious insider collecting records en masse.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=10)

        access_count = (
            db.query(func.count(Log.id))
            .filter(
                Log.actor_id == actor_id,
                Log.event_type.in_(["RECORD_VIEW", "FILE_DOWNLOAD", "DATA_ACCESS"]),
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if access_count > 100:

            alert_key = f"BULK_DATA_ACCESS:{actor_id}:{bucket}"

            alert = Alert(
                rule_name="BULK_DATA_ACCESS",
                severity="HIGH",
                actor_id=actor_id,
                alert_key=alert_key,
                description="Actor accessed more than 100 records within 10 minutes",
                context={"access_count": access_count}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


# ── SYSTEM HEALTH ─────────────────────────────

def detect_service_downtime_cascade(db: Session):
    """
    Service Downtime Cascade
    Trigger : >5 distinct services report SERVICE_UNAVAILABLE within 3 minutes.
    Severity: CRITICAL

    A single service going down is a routine incident. Multiple services
    failing simultaneously points to a cascading failure, infrastructure
    outage, or a targeted attack (e.g. resource exhaustion / DDoS) that
    is spreading across the system.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=3)

        affected_services = (
            db.query(func.count(func.distinct(Log.service)))
            .filter(
                Log.event_type == "SERVICE_UNAVAILABLE",
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if affected_services > 5:

            alert_key = f"SERVICE_DOWNTIME_CASCADE:{bucket}"

            alert = Alert(
                rule_name="SERVICE_DOWNTIME_CASCADE",
                severity="CRITICAL",
                alert_key=alert_key,
                description="More than 5 distinct services reported unavailable within 3 minutes",
                context={"affected_service_count": affected_services}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()


def detect_database_health_degradation(db: Session):
    """
    Database Health Degradation
    Trigger : >20 DB-related errors (DB_QUERY_SLOW or DB_CONNECTION_FAILED)
              within 2 minutes.
    Severity: HIGH

    A slow query here and there is normal. A burst of DB errors in a short
    window signals connection pool exhaustion, a runaway query, disk pressure,
    or a failing DB node — all of which need immediate attention before they
    cause full service outages.
    """
    try:

        now = datetime.utcnow()
        bucket = now.strftime("%Y-%m-%d-%H-%M")

        window_start = now - timedelta(minutes=2)

        db_error_count = (
            db.query(func.count(Log.id))
            .filter(
                Log.event_type.in_(["DB_QUERY_SLOW", "DB_CONNECTION_FAILED"]),
                Log.timestamp >= window_start
            )
            .scalar()
        )

        if db_error_count > 20:

            alert_key = f"DB_HEALTH_DEGRADATION:{bucket}"

            alert = Alert(
                rule_name="DB_HEALTH_DEGRADATION",
                severity="HIGH",
                alert_key=alert_key,
                description="More than 20 DB errors detected within 2 minutes",
                context={"db_error_count": db_error_count}
            )

            db.add(alert)
            db.commit()

    except IntegrityError:
        db.rollback()