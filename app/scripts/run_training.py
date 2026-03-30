import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.database import SessionLocal
from app.ml.trainer import train_model

def main():
    print("Starting ML training job...")
    db = SessionLocal()
    try:
        success = train_model(db)
        if success:
            print("\nTraining complete. Model saved to models/")
            print("Next step: verify with scripts/verify.py")
        else:
            print("\nTraining skipped — check output above for reason.")
    finally:
        db.close()

if __name__ == "__main__":
    main()