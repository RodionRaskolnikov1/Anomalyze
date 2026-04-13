import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from app.db.database import SessionLocal, Base, engine
from app.models import log, alerts as alerts_model, training_log  
Base.metadata.create_all(bind=engine)

from app.models.log import Log
from app.services.detection_service import run_detection_rules

def backfill():
    db = SessionLocal()
    try:
        from app.models.alerts import Alert
        existing_alerts = db.query(Alert).count()
        if existing_alerts > 10:
            print(f"Alerts table already has {existing_alerts} alerts. Skipping backfill.")
            return

        logs = db.query(Log).all()
        print(f"Running detection on {len(logs)} logs...")

        for i, log_entry in enumerate(logs):
            run_detection_rules(db, log_entry)
            if (i + 1) % 200 == 0:
                print(f"  Processed {i + 1}/{len(logs)}")

        db.commit()

        alert_count = db.query(Alert).count()
        print(f"Done. {alert_count} alerts generated.")
    finally:
        db.close()

if __name__ == "__main__":
    backfill()