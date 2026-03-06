from sqlalchemy.orm import Session
from app.models.alerts import Alert


def get_alerts(
    db: Session,
    rule_name=None,
    severity=None,
    ip_address=None,
    actor_id=None,
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

    return query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()