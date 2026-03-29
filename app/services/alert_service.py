from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.alerts import Alert
from app.core.enums import AlertStatus
from app.schemas.alert_schema import AlertUpdate


def get_alerts(
    db: Session,
    rule_name=None,
    severity=None,
    ip_address=None,
    actor_id=None,
    alert_status=None,
    limit=100,
    offset=0
):
    query = db.query(Alert)

    if rule_name:
        query = query.filter(Alert.rule_name == rule_name)

    if severity:
        query = query.filter(Alert.severity == severity)

    if ip_address:
        query = query.filter(Alert.ip_address == ip_address)

    if actor_id:
        query = query.filter(Alert.actor_id == actor_id)

    if alert_status:
        query = query.filter(Alert.status == alert_status)

    return query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()


def update_alert(db: Session, alert_id: str, payload: AlertUpdate) -> Alert:

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found.",
        )

    now = datetime.now(timezone.utc)

    if payload.status is not None:
        alert.status = payload.status

        # Set timestamps automatically on transition
        if payload.status == AlertStatus.ACKNOWLEDGED and alert.acknowledged_at is None:
            alert.acknowledged_at = now

        if payload.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = now

    if payload.notes is not None:
        alert.notes = payload.notes

    db.commit()
    db.refresh(alert)
    return alert