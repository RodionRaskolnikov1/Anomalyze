from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services import analytics_service
from app.services.threat_score import (
    score_ip,
    score_actor,
    top_threat_ips,
    top_threat_actors,
)

router = APIRouter(prefix="/analytics", tags=["analytics"])


# ── Summary KPIs ─────────────────────────────────────────────────────────────

@router.get("/summary")
def get_summary(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """
    Headline KPIs: total alerts, critical count, unique IPs/actors,
    most-triggered rule. Designed for a dashboard stat-card row.
    """
    return analytics_service.summary_stats(db, hours=hours)


# ── Time-series ───────────────────────────────────────────────────────────────

@router.get("/alerts-over-time")
def get_alerts_over_time(
    hours: int          = Query(24, ge=1, le=168),
    bucket_minutes: int = Query(30, ge=5, le=360),
    db: Session         = Depends(get_db),
):
    """
    Alert counts per time bucket, split by severity.
    Suitable for a stacked area / line chart.
    """
    return analytics_service.alerts_over_time(db, hours=hours, bucket_minutes=bucket_minutes)


# ── Pie / Donut ───────────────────────────────────────────────────────────────

@router.get("/severity-distribution")
def get_severity_distribution(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Alert counts grouped by severity. Suitable for a donut chart."""
    return analytics_service.severity_distribution(db, hours=hours)


# ── Bar chart ─────────────────────────────────────────────────────────────────

@router.get("/rule-breakdown")
def get_rule_breakdown(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(15, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Top triggered rules by count. Suitable for a horizontal bar chart."""
    return analytics_service.rule_breakdown(db, hours=hours, limit=limit)


# ── Heatmap ───────────────────────────────────────────────────────────────────

@router.get("/hourly-heatmap")
def get_hourly_heatmap(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
):
    """
    7×24 matrix of alert counts (weekday × hour).
    Suitable for a calendar heatmap showing attack timing patterns.
    """
    return analytics_service.hourly_heatmap(db, days=days)


# ── Top attacking IPs ─────────────────────────────────────────────────────────

@router.get("/top-ips")
def get_top_ips(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Top IPs by alert volume with per-severity breakdown (stacked bar)."""
    return analytics_service.top_ips(db, hours=hours, limit=limit)


# ── Threat scoring ────────────────────────────────────────────────────────────

@router.get("/threat-score/ip/{ip_address}")
def get_ip_threat_score(
    ip_address: str,
    window_hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """
    Composite 0-100 threat score for a single IP address.
    Factors in severity weights, alert volume, rule variety,
    recency, and ML anomaly flag.
    """
    return score_ip(db, ip_address, window_hours=window_hours)


@router.get("/threat-score/actor/{actor_id}")
def get_actor_threat_score(
    actor_id: str,
    window_hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
):
    """Composite 0-100 threat score for a single actor."""
    return score_actor(db, actor_id, window_hours=window_hours)


@router.get("/threat-leaderboard/ips")
def get_top_threat_ips(
    window_hours: int = Query(24, ge=1, le=168),
    limit: int        = Query(20, ge=1, le=100),
    db: Session       = Depends(get_db),
):
    """
    Ranked list of top threat IPs by composite score.
    Each entry includes score, tier, alert count, and triggered rules.
    """
    return top_threat_ips(db, window_hours=window_hours, limit=limit)


@router.get("/threat-leaderboard/actors")
def get_top_threat_actors(
    window_hours: int = Query(24, ge=1, le=168),
    limit: int        = Query(20, ge=1, le=100),
    db: Session       = Depends(get_db),
):
    """Ranked list of top threat actors by composite score."""
    return top_threat_actors(db, window_hours=window_hours, limit=limit)
