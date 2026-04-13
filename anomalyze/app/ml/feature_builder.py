import logging
from datetime import datetime, timedelta, timezone

import pandas as pd
from sqlalchemy import func, case, extract
from sqlalchemy.orm import Session

from app.models.log import Log

logger = logging.getLogger(__name__)

# These must stay in sync with trainer.py and anomaly_detector.py.
# Any column added here must also appear in FEATURE_COLS there.
FEATURE_COLS = [
    "request_count",
    "failed_login_ratio",
    "unique_actors",
    "unique_user_agents",
    "error_rate",
    "requests_per_minute",
    "off_hours_ratio",
    "admin_action_count",
]

_ADMIN_EVENTS = [
    "ADMIN_DELETE_USER",
    "ADMIN_BAN_USER",
    "ADMIN_ROLE_CHANGE",
    "ADMIN_EXPORT_DATA",
]


def build_ip_features(
    db: Session,
    *,
    days: int = 0,
    minutes: int = 0,
) -> pd.DataFrame:
    """
    Build per-IP feature DataFrame for the given time window.

    Exactly one of `days` or `minutes` must be non-zero.

    Args:
        db:      SQLAlchemy session.
        days:    Look back N days  (use for training).
        minutes: Look back N mins  (use for inference).

    Returns:
        DataFrame with columns: ["ip_address"] + FEATURE_COLS.
        Empty DataFrame if there's no data in the window.
    """
    if not days and not minutes:
        raise ValueError("Provide either days= or minutes= for the feature window.")

    now = datetime.now(timezone.utc)

    if days:
        window_start = now - timedelta(days=days)
        window_minutes = days * 24 * 60
    else:
        window_start = now - timedelta(minutes=minutes)
        window_minutes = minutes

    logger.info(
        "Building IP features | window=%s | from=%s",
        f"{days}d" if days else f"{minutes}m",
        window_start.strftime("%Y-%m-%d %H:%M"),
    )

    ua_expr = Log.context["user_agent"].as_string()

    rows = (
        db.query(
            Log.ip_address,

            func.count(Log.id).label("request_count"),

            func.sum(
                case((Log.event_type == "AUTH_LOGIN_FAILED", 1), else_=0)
            ).label("failed_logins"),

            func.count(func.distinct(Log.actor_id)).label("unique_actors"),

            func.count(
                func.distinct(ua_expr)
            ).label("unique_user_agents"),

            func.sum(
                case(
                    (Log.event_type.in_(["API_ERROR"]), 1),
                    else_=0
                )
            ).label("error_count"),

            # off_hours: hour < 5 OR hour >= 23  (UTC)
            func.sum(
                case(
                    (
                        (extract("hour", Log.timestamp) < 5) |
                        (extract("hour", Log.timestamp) >= 23),
                        1
                    ),
                    else_=0
                )
            ).label("off_hours_count"),

            func.sum(
                case(
                    (Log.event_type.in_(_ADMIN_EVENTS), 1),
                    else_=0
                )
            ).label("admin_action_count"),
        )
        .filter(
            Log.ip_address.isnot(None),
            Log.timestamp >= window_start,
        )
        .group_by(Log.ip_address)
        .all()
    )

    if not rows:
        logger.warning("No log data found in the feature window.")
        return pd.DataFrame(columns=["ip_address"] + FEATURE_COLS)

    data = []
    for r in rows:
        rc = r.request_count or 1  # guard against zero division

        data.append({
            "ip_address":         r.ip_address,
            "request_count":      r.request_count,
            "failed_login_ratio": (r.failed_logins or 0) / rc,
            "unique_actors":      r.unique_actors or 0,
            "unique_user_agents": r.unique_user_agents or 0,
            "error_rate":         (r.error_count or 0) / rc,
            "requests_per_minute": r.request_count / max(window_minutes, 1),
            "off_hours_ratio":    (r.off_hours_count or 0) / rc,
            "admin_action_count": r.admin_action_count or 0,
        })

    df = pd.DataFrame(data)
    logger.info("Feature matrix built: %d IPs × %d features", len(df), len(FEATURE_COLS))
    return df