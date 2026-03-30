import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.database import SessionLocal
from app.models.log import Log
from app.models.training_log import ModelTrainingLog
from app.ml.feature_builder import build_ip_features
from app.ml.model_store import model_exists
from app.ml.anomaly_detector import run_inference

ATTACKER_IPS = {"203.0.113.10", "198.51.100.55", "192.0.2.77", "172.16.99.4"}

def check(label, passed, detail=""):
    status = "✓" if passed else "✗"
    print(f"  [{status}] {label}")
    if detail:
        print(f"        {detail}")
    return passed


def main():
    print("\n=== Anomalyze Pipeline Verification ===\n")
    db = SessionLocal()
    all_passed = True

    # ── 1. Log count ──────────────────────────────────────────────
    log_count = db.query(Log).count()
    ok = check(
        "Database has enough logs",
        log_count >= 100,
        f"{log_count} log entries found (need >= 100)"
    )
    all_passed = all_passed and ok

    # ── 2. Feature builder ────────────────────────────────────────
    df = build_ip_features(db, days=30)
    ok = check(
        "Feature builder produces valid matrix",
        len(df) >= 5,
        f"{len(df)} IPs × {len(df.columns)-1} features"
    )
    all_passed = all_passed and ok

    if not df.empty:
        print(f"\n  Feature matrix sample (top 5 IPs by request count):")
        top = df.nlargest(5, "request_count")[["ip_address", "request_count", "failed_login_ratio", "error_rate", "off_hours_ratio"]]
        for _, row in top.iterrows():
            print(f"    {row['ip_address']:<20} requests={int(row['request_count']):<6} "
                  f"failed_ratio={row['failed_login_ratio']:.2f}  "
                  f"error_rate={row['error_rate']:.2f}  "
                  f"off_hours={row['off_hours_ratio']:.2f}")

    # ── 3. Model on disk ──────────────────────────────────────────
    print()
    ok = check(
        "ML model exists on disk",
        model_exists(),
        "models/isolation_forest.pkl + models/scaler.pkl"
    )
    all_passed = all_passed and ok

    # ── 4. Inference runs ─────────────────────────────────────────
    if not df.empty and model_exists():
        result = run_inference(df)
        n_flagged = result["is_anomaly"].sum()
        ok = check(
            "Inference runs without error",
            True,
            f"{n_flagged} IPs flagged as anomalous out of {len(result)}"
        )

        # ── 5. Attacker IPs flagged ───────────────────────────────
        print(f"\n  Anomaly scores for known attacker IPs:")
        found_attackers = 0
        for _, row in result.iterrows():
            if row["ip_address"] in ATTACKER_IPS:
                found_attackers += 1
                flag = "⚠ FLAGGED" if row["is_anomaly"] else "  normal"
                print(f"    {row['ip_address']:<20} score={row['anomaly_score']:>5.1f}/100  {flag}")

        if found_attackers == 0:
            print("    (No attacker IPs found in recent window — use days=30 data)")

        ok = check(
            "At least one attacker IP flagged",
            n_flagged > 0,
        )
        all_passed = all_passed and ok
    else:
        print()
        check("Inference skipped", False, "Need both data and a trained model")

    # ── 6. Training log ───────────────────────────────────────────
    print()
    training_runs = db.query(ModelTrainingLog).count()
    ok = check(
        "Training log has entries",
        training_runs > 0,
        f"{training_runs} training run(s) recorded"
    )
    all_passed = all_passed and ok

    if training_runs > 0:
        latest = db.query(ModelTrainingLog).order_by(ModelTrainingLog.trained_at.desc()).first()
        print(f"\n  Latest training run:")
        print(f"    Status:       {latest.status}")
        print(f"    Trained at:   {latest.trained_at}")
        print(f"    Samples:      {latest.sample_count}")
        print(f"    Anomaly rate: {latest.anomaly_rate} (expected ~{latest.contamination})")
        print(f"    Elapsed:      {latest.elapsed_seconds}s")

    db.close()

    print(f"\n{'='*40}")
    if all_passed:
        print("All checks passed. Anomalyze is fully operational.")
        print("\nStart the server:  uvicorn app.main:app --reload")
        print("Hit the API:       curl -H 'X-API-Key: your-key' http://localhost:8000/health")
    else:
        print("Some checks failed. See above for details.")
        print("\nQuick fix:")
        print("  1. python scripts/seed.py")
        print("  2. python scripts/run_training.py")
        print("  3. python scripts/verify.py")

    print()


if __name__ == "__main__":
    main()