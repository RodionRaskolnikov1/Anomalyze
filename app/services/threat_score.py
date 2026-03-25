"""
Threat Scoring Engine
=====================
Computes a 0-100 composite risk score for every IP address and actor that
has activity in the last configurable window.

Score components
----------------
  - Alert severity weights   (CRITICAL=40, HIGH=25, MEDIUM=10, LOW=3)
  - Alert volume bonus       (logarithmic, caps at +20)
  - Distinct rule variety    (each unique rule_name adds +5, caps at +15)
  - Recency amplifier        (alerts in last 10 min multiply sub-score × 1.5)
  - ML anomaly flag          (flat +20 if ML_TRAFFIC_ANOMALY present)

The result is clamped to [0, 100] and bucketed into a tier:
  CRITICAL >= 75 | HIGH >= 50 | MEDIUM >= 25 | LOW < 25
"""

import math
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alerts import Alert


_SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   10,
    "LOW":       3,
}

_TIER_THRESHOLDS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (0,  "LOW"),
]


def _score_tier(score: float) -> str:
    for threshold, label in _TIER_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def _compute_score(
    alerts: list[Alert],
    recent_cutoff: datetime,
) -> float:
    if not alerts:
        return 0.0

    base = 0.0
    has_recent = any(a.created_at >= recent_cutoff for a in alerts)
    unique_rules = {a.rule_name for a in alerts}
    has_ml = any(a.rule_name == "ML_TRAFFIC_ANOMALY" for a in alerts)

    # Severity weights
    severity_sum = sum(_SEVERITY_WEIGHT.get(a.severity, 3) for a in alerts)
    base += severity_sum

    # Volume bonus (log scale, cap at 20)
    volume_bonus = min(math.log1p(len(alerts)) * 5, 20)
    base += volume_bonus

    # Rule variety bonus (cap at 15)
    variety_bonus = min(len(unique_rules) * 5, 15)
    base += variety_bonus

    # ML anomaly flat bonus
    if has_ml:
        base += 20

    # Recency amplifier
    if has_recent:
        base *= 1.5

    return min(base, 100.0)


def score_ip(db: Session, ip_address: str, window_hours: int = 24) -> dict:
    """Return a threat score dict for a single IP."""
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    recent_cutoff = datetime.utcnow() - timedelta(minutes=10)

    alerts = (
        db.query(Alert)
        .filter(Alert.ip_address == ip_address, Alert.created_at >= cutoff)
        .all()
    )

    score = _compute_score(alerts, recent_cutoff)
    return {
        "ip_address":   ip_address,
        "score":        round(score, 1),
        "tier":         _score_tier(score),
        "alert_count":  len(alerts),
        "unique_rules": list({a.rule_name for a in alerts}),
        "window_hours": window_hours,
    }


def score_actor(db: Session, actor_id: str, window_hours: int = 24) -> dict:
    """Return a threat score dict for a single actor."""
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    recent_cutoff = datetime.utcnow() - timedelta(minutes=10)

    alerts = (
        db.query(Alert)
        .filter(Alert.actor_id == actor_id, Alert.created_at >= cutoff)
        .all()
    )

    score = _compute_score(alerts, recent_cutoff)
    return {
        "actor_id":     actor_id,
        "score":        round(score, 1),
        "tier":         _score_tier(score),
        "alert_count":  len(alerts),
        "unique_rules": list({a.rule_name for a in alerts}),
        "window_hours": window_hours,
    }


def top_threat_ips(
    db: Session,
    window_hours: int = 24,
    limit: int = 20,
) -> list[dict]:
    """
    Return the top-N IPs ranked by threat score.
    Runs a single aggregation query to get candidates, then scores them.
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    rows = (
        db.query(Alert.ip_address, func.count(Alert.id).label("cnt"))
        .filter(Alert.ip_address.isnot(None), Alert.created_at >= cutoff)
        .group_by(Alert.ip_address)
        .order_by(func.count(Alert.id).desc())
        .limit(limit * 2)          # over-fetch so scoring can reorder
        .all()
    )

    results = [score_ip(db, row.ip_address, window_hours) for row in rows]
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:limit]


def top_threat_actors(
    db: Session,
    window_hours: int = 24,
    limit: int = 20,
) -> list[dict]:
    """Return the top-N actors ranked by threat score."""
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    rows = (
        db.query(Alert.actor_id, func.count(Alert.id).label("cnt"))
        .filter(Alert.actor_id.isnot(None), Alert.created_at >= cutoff)
        .group_by(Alert.actor_id)
        .order_by(func.count(Alert.id).desc())
        .limit(limit * 2)
        .all()
    )

    results = [score_actor(db, row.actor_id, window_hours) for row in rows]
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:limit]
