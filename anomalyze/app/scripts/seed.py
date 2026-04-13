import random
import uuid
import sys
import os
from datetime import datetime, timedelta, timezone

# ── Make sure app is importable from project root ─────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.db.database import SessionLocal, Base, engine1
from app.models.log import Log
from app.core.enums import LogLevel

# Create tables if they don't exist yet
from app.models import log, alerts as alerts_model, training_log  # noqa
Base.metadata.create_all(bind=engine1)

random.seed(42)

# ── IP pools ──────────────────────────────────────────────────────

NORMAL_IPS = [
    f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(120)
]


BRUTE_FORCE_IP  = "203.0.113.10"   # floods failed logins
SCRAPER_IP      = "198.51.100.55"  # rotates user agents, high API volume
EXFIL_IP        = "192.0.2.77"     # bulk data access + admin exports
OFF_HOURS_IP    = "172.16.99.4"    # only active 1am-4am UTC

ALL_IPS = NORMAL_IPS + [BRUTE_FORCE_IP, SCRAPER_IP, EXFIL_IP, OFF_HOURS_IP]

# ── Actor pools ───────────────────────────────────────────────────

NORMAL_ACTORS  = [f"user_{i:04d}" for i in range(1, 51)]
ADMIN_ACTORS   = [f"admin_{i:02d}" for i in range(1, 6)]
ALL_ACTORS     = NORMAL_ACTORS + ADMIN_ACTORS

# ── Services ──────────────────────────────────────────────────────

SERVICES = ["auth-service", "api-gateway", "user-service", "data-service", "admin-panel"]

# ── User agents ───────────────────────────────────────────────────

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121",
]

BOT_UAS = [f"python-requests/2.{i}.0" for i in range(28, 42)] + \
          [f"curl/7.{i}.0" for i in range(60, 75)] + \
          [f"Go-http-client/1.{i}" for i in range(10, 20)]


# ── Time helpers ──────────────────────────────────────────────────

def random_business_hours_ts(days_ago_max=30) -> datetime:
    """Random timestamp during business hours (9am-6pm UTC) in the last 30 days."""
    now = datetime.now(timezone.utc)
    base = now - timedelta(days=random.uniform(0, days_ago_max))
    return base.replace(hour=random.randint(9, 17), minute=random.randint(0, 59), second=random.randint(0, 59))


def random_ts(days_ago_max=30) -> datetime:
    """Fully random timestamp across last 30 days."""
    now = datetime.now(timezone.utc)
    return now - timedelta(
        days=random.uniform(0, days_ago_max),
        hours=random.uniform(0, 24),
        minutes=random.uniform(0, 60),
    )


def off_hours_ts(days_ago_max=30) -> datetime:
    """Random timestamp between 1am-4am UTC — off hours."""
    now = datetime.now(timezone.utc)
    base = now - timedelta(days=random.uniform(0, days_ago_max))
    return base.replace(hour=random.randint(1, 3), minute=random.randint(0, 59), second=random.randint(0, 59))


# ── Log builders ─────────────────────────────────────────────────

def make_log(service, event_type, level, ip, actor=None, message=None, context=None, ts=None):
    return Log(
        id=uuid.uuid4(),
        service=service,
        event_type=event_type,
        level=level,
        message=message,
        actor_id=actor,
        ip_address=ip,
        request_id=str(uuid.uuid4()),
        timestamp=ts or random_business_hours_ts(),
        context=context or {},
    )


# ── Generate logs ─────────────────────────────────────────────────

def generate_normal_traffic(count=800):
    """Normal users doing normal things."""
    logs = []
    events = [
        ("AUTH_LOGIN_SUCCESS", LogLevel.INFO,    "User logged in successfully"),
        ("AUTH_LOGIN_FAILED",  LogLevel.WARNING, "Invalid credentials"),
        ("AUTH_LOGOUT",        LogLevel.INFO,    "User logged out"),
        ("API_REQUEST",        LogLevel.INFO,    "API request processed"),
        ("RECORD_VIEW",        LogLevel.INFO,    "Record accessed"),
        ("USER_UPDATED",       LogLevel.INFO,    "Profile updated"),
        ("PASSWORD_CHANGE",    LogLevel.INFO,    "Password changed"),
    ]
    for _ in range(count):
        ip     = random.choice(NORMAL_IPS)
        actor  = random.choice(NORMAL_ACTORS)
        event, level, msg = random.choice(events)
        ua = random.choice(NORMAL_UAS)
        logs.append(make_log(
            service=random.choice(SERVICES),
            event_type=event,
            level=level,
            ip=ip,
            actor=actor,
            message=msg,
            context={"user_agent": ua},
            ts=random_business_hours_ts(),
        ))
    return logs


def generate_brute_force(count=200):
    """One IP hammering AUTH_LOGIN_FAILED against many accounts."""
    logs = []
    for _ in range(count):
        actor = random.choice(ALL_ACTORS)
        logs.append(make_log(
            service="auth-service",
            event_type="AUTH_LOGIN_FAILED",
            level=LogLevel.WARNING,
            ip=BRUTE_FORCE_IP,
            actor=actor,
            message="Authentication failed — brute force suspected",
            context={"user_agent": random.choice(NORMAL_UAS), "attempt": random.randint(1, 20)},
            ts=random_ts(),
        ))
    return logs


def generate_scraper(count=250):
    """One IP making massive API_REQUEST volume with rotating user agents."""
    logs = []
    for _ in range(count):
        ua = random.choice(BOT_UAS)
        event = random.choices(
            ["API_REQUEST", "API_ERROR"],
            weights=[0.65, 0.35],
        )[0]
        level = LogLevel.INFO if event == "API_REQUEST" else LogLevel.ERROR
        logs.append(make_log(
            service="api-gateway",
            event_type=event,
            level=level,
            ip=SCRAPER_IP,
            actor=random.choice(NORMAL_ACTORS),
            message="High-volume API access",
            context={"user_agent": ua, "endpoint": f"/api/v1/resource/{random.randint(1,9999)}"},
            ts=random_ts(),
        ))
    return logs


def generate_exfiltration(count=150):
    """One actor doing bulk DATA_ACCESS and repeated ADMIN_EXPORT_DATA."""
    logs = []
    actor = "admin_01"
    for _ in range(count):
        event = random.choices(
            ["DATA_ACCESS", "RECORD_VIEW", "FILE_DOWNLOAD", "ADMIN_EXPORT_DATA"],
            weights=[0.4, 0.3, 0.2, 0.1],
        )[0]
        logs.append(make_log(
            service="data-service",
            event_type=event,
            level=LogLevel.INFO,
            ip=EXFIL_IP,
            actor=actor,
            message="Data access event",
            context={"user_agent": random.choice(NORMAL_UAS), "record_id": str(uuid.uuid4())},
            ts=random_ts(),
        ))
    return logs


def generate_off_hours(count=120):
    """Normal-looking traffic but exclusively between 1am-4am."""
    logs = []
    events = [
        ("API_REQUEST",       LogLevel.INFO,    "API request"),
        ("AUTH_LOGIN_SUCCESS", LogLevel.INFO,   "Login successful"),
        ("RECORD_VIEW",       LogLevel.INFO,    "Record viewed"),
        ("DATA_ACCESS",       LogLevel.INFO,    "Data accessed"),
    ]
    for _ in range(count):
        event, level, msg = random.choice(events)
        logs.append(make_log(
            service=random.choice(SERVICES),
            event_type=event,
            level=level,
            ip=OFF_HOURS_IP,
            actor=random.choice(NORMAL_ACTORS),
            message=msg,
            context={"user_agent": random.choice(NORMAL_UAS)},
            ts=off_hours_ts(),
        ))
    return logs


def generate_system_noise(count=100):
    """Background system errors and DB events."""
    logs = []
    events = [
        ("SYSTEM_ERROR",        LogLevel.ERROR,    "Unhandled exception in service"),
        ("DB_QUERY_SLOW",       LogLevel.WARNING,  "Query exceeded 2s threshold"),
        ("DB_CONNECTION_FAILED", LogLevel.ERROR,   "Database connection refused"),
        ("SERVICE_UNAVAILABLE", LogLevel.CRITICAL, "Service health check failed"),
    ]
    for _ in range(count):
        event, level, msg = random.choice(events)
        logs.append(make_log(
            service=random.choice(SERVICES),
            event_type=event,
            level=level,
            ip=random.choice(NORMAL_IPS),
            message=msg,
            context={},
            ts=random_ts(),
        ))
    return logs


# ── Main ──────────────────────────────────────────────────────────

def seed():
    db = SessionLocal()

    existing = db.query(Log).count()
    if existing > 10:
        print(f"Database already has {existing} log entries. Skipping seed.")
        print("If you want to re-seed, delete anomaly.db and run again.")
        db.close()
        return

    print("Generating seed data...")

    all_logs = (
        generate_normal_traffic(800)   +
        generate_brute_force(200)      +
        generate_scraper(250)          +
        generate_exfiltration(150)     +
        generate_off_hours(120)        +
        generate_system_noise(100)
    )

    random.shuffle(all_logs)

    print(f"Inserting {len(all_logs)} log entries...")

    # Batch insert — much faster than one-by-one commits
    batch_size = 200
    for i in range(0, len(all_logs), batch_size):
        batch = all_logs[i:i + batch_size]
        db.bulk_save_objects(batch)
        db.commit()
        print(f"  Inserted {min(i + batch_size, len(all_logs))}/{len(all_logs)}")

    db.close()
    print(f"\nDone. {len(all_logs)} logs inserted across 24 IPs.")
    print("\nIP breakdown:")
    print(f"  Normal IPs  (x20): regular business-hours traffic")
    print(f"  {BRUTE_FORCE_IP}  : brute force — floods AUTH_LOGIN_FAILED")
    print(f"  {SCRAPER_IP}   : scraper — rotates user agents, high API volume")
    print(f"  {EXFIL_IP}    : exfiltration — bulk DATA_ACCESS + ADMIN_EXPORT_DATA")
    print(f"  {OFF_HOURS_IP}     : off-hours — all traffic between 1am-4am UTC")
    print("\nNext step: run the trainer")
    print("  python scripts/run_training.py")


if __name__ == "__main__":
    seed()