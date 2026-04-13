"""
Analytics Service
=================
Produces chart-ready JSON payloads for every analytics endpoint.

All queries run against the alerts table (SQLite in dev, PostgreSQL in prod).
Heavy aggregations use SQLAlchemy core expressions so they translate cleanly
across both dialects.
"""

from datetime import datetime, timedelta
from collections import defaultdict

from sqlalchemy import func, case, text
from sqlalchemy.orm import Session

from app.models.alerts import Alert
from app.models.log import Log


# ─────────────────────────────────────────────────────────────────────────────
# ALERT TIME-SERIES
# ─────────────────────────────────────────────────────────────────────────────

def alerts_over_time(
    db: Session,
    hours: int = 24,
    bucket_minutes: int = 30,
) -> dict:
    """
    Returns alert counts bucketed into `bucket_minutes` intervals over the
    last `hours` hours. Suitable for a line / area chart.

    Response shape:
      {
        "labels":   ["2024-01-01 00:00", "2024-01-01 00:30", ...],
        "datasets": {
          "CRITICAL": [0, 2, 1, ...],
          "HIGH":     [...],
          "MEDIUM":   [...],
          "LOW":      [...]
        }
      }
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)
    total_buckets = (hours * 60) // bucket_minutes

    # Build ordered bucket list
    bucket_starts = [
        cutoff + timedelta(minutes=i * bucket_minutes)
        for i in range(total_buckets)
    ]

    alerts = (
        db.query(Alert.created_at, Alert.severity)
        .filter(Alert.created_at >= cutoff)
        .all()
    )

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts: dict[str, list[int]] = {s: [0] * total_buckets for s in severities}

    for created_at, severity in alerts:
        elapsed = (created_at - cutoff).total_seconds() / 60
        idx = int(elapsed // bucket_minutes)
        if 0 <= idx < total_buckets:
            sev = severity if severity in severities else "LOW"
            counts[sev][idx] += 1

    labels = [b.strftime("%Y-%m-%d %H:%M") for b in bucket_starts]

    return {
        "labels":   labels,
        "datasets": counts,
        "meta": {
            "hours":          hours,
            "bucket_minutes": bucket_minutes,
            "total_alerts":   len(alerts),
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY DISTRIBUTION
# ─────────────────────────────────────────────────────────────────────────────

def severity_distribution(db: Session, hours: int = 24) -> dict:
    """
    Returns alert counts by severity. Suitable for a pie / donut chart.

    Response shape:
      {
        "labels": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "values": [3, 14, 22, 5]
      }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    rows = (
        db.query(Alert.severity, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= cutoff)
        .group_by(Alert.severity)
        .all()
    )

    counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for row in rows:
        if row.severity in counts:
            counts[row.severity] = row.cnt
        else:
            counts["LOW"] += row.cnt

    return {
        "labels": list(counts.keys()),
        "values": list(counts.values()),
        "meta":   {"hours": hours},
    }


# ─────────────────────────────────────────────────────────────────────────────
# RULE BREAKDOWN
# ─────────────────────────────────────────────────────────────────────────────

def rule_breakdown(db: Session, hours: int = 24, limit: int = 15) -> dict:
    """
    Returns top triggered rules by count. Suitable for a horizontal bar chart.

    Response shape:
      {
        "labels": ["BRUTE_FORCE_LOGIN", "REQUEST_FLOOD", ...],
        "values": [45, 30, ...]
      }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    rows = (
        db.query(Alert.rule_name, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= cutoff)
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )

    return {
        "labels": [r.rule_name for r in rows],
        "values": [r.cnt for r in rows],
        "meta":   {"hours": hours},
    }


# ─────────────────────────────────────────────────────────────────────────────
# HOURLY HEATMAP
# ─────────────────────────────────────────────────────────────────────────────

def hourly_heatmap(db: Session, days: int = 7) -> dict:
    """
    Returns a 7×24 matrix of alert counts (day-of-week × hour-of-day).
    Suitable for a heatmap / calendar chart.

    Response shape:
      {
        "days":    ["Mon", "Tue", ..., "Sun"],
        "hours":   [0, 1, ..., 23],
        "matrix":  [[int, ...], ...]   # shape: 7 × 24
      }
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    alerts = (
        db.query(Alert.created_at)
        .filter(Alert.created_at >= cutoff)
        .all()
    )

    # matrix[weekday][hour]  (weekday: 0=Mon … 6=Sun)
    matrix = [[0] * 24 for _ in range(7)]

    for (created_at,) in alerts:
        matrix[created_at.weekday()][created_at.hour] += 1

    return {
        "days":   ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "hours":  list(range(24)),
        "matrix": matrix,
        "meta":   {"days": days},
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOP ATTACKING IPs
# ─────────────────────────────────────────────────────────────────────────────

def top_ips(db: Session, hours: int = 24, limit: int = 10) -> dict:
    """
    Returns top IPs by alert volume with per-severity breakdown.
    Suitable for a stacked bar chart.

    Response shape:
      {
        "ips": ["1.2.3.4", ...],
        "datasets": {
          "CRITICAL": [2, 0, ...],
          "HIGH":     [5, 3, ...],
          ...
        }
      }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    rows = (
        db.query(
            Alert.ip_address,
            Alert.severity,
            func.count(Alert.id).label("cnt"),
        )
        .filter(Alert.ip_address.isnot(None), Alert.created_at >= cutoff)
        .group_by(Alert.ip_address, Alert.severity)
        .all()
    )

    # Aggregate by IP
    ip_totals: dict[str, int] = defaultdict(int)
    ip_sev: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for ip, sev, cnt in rows:
        ip_totals[ip] += cnt
        ip_sev[ip][sev] += cnt

    top = sorted(ip_totals, key=ip_totals.get, reverse=True)[:limit]

    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    datasets = {s: [ip_sev[ip].get(s, 0) for ip in top] for s in severities}

    return {
        "ips":      top,
        "datasets": datasets,
        "meta":     {"hours": hours},
    }


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY STATS  (for a "KPI cards" row)
# ─────────────────────────────────────────────────────────────────────────────

def summary_stats(db: Session, hours: int = 24) -> dict:
    """
    Returns headline KPIs for a stats card row.

    Response shape:
      {
        "total_alerts":       42,
        "critical_alerts":     3,
        "unique_ips":         18,
        "unique_actors":       7,
        "most_triggered_rule": "BRUTE_FORCE_LOGIN",
        "hours":              24
      }
    """
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    total = db.query(func.count(Alert.id)).filter(Alert.created_at >= cutoff).scalar() or 0

    critical = (
        db.query(func.count(Alert.id))
        .filter(Alert.created_at >= cutoff, Alert.severity == "CRITICAL")
        .scalar() or 0
    )

    unique_ips = (
        db.query(func.count(func.distinct(Alert.ip_address)))
        .filter(Alert.ip_address.isnot(None), Alert.created_at >= cutoff)
        .scalar() or 0
    )

    unique_actors = (
        db.query(func.count(func.distinct(Alert.actor_id)))
        .filter(Alert.actor_id.isnot(None), Alert.created_at >= cutoff)
        .scalar() or 0
    )

    top_rule_row = (
        db.query(Alert.rule_name, func.count(Alert.id).label("cnt"))
        .filter(Alert.created_at >= cutoff)
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .first()
    )

    return {
        "total_alerts":        total,
        "critical_alerts":     critical,
        "unique_ips":          unique_ips,
        "unique_actors":       unique_actors,
        "most_triggered_rule": top_rule_row.rule_name if top_rule_row else None,
        "hours":               hours,
    }
