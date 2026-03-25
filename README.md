# Log Analyzer — Security SIEM Backend

A production-grade FastAPI backend for ingesting service logs, detecting threats in real time, running ML-based anomaly detection, and serving chart-ready analytics data.

---

## Features

### Core
- **Log Ingestion** — `POST /logs` with automatic event normalization (fuzzy keyword matching → canonical event types)
- **Rule-Based Detection** — 12 detection rules fire synchronously on every log entry
- **ML Anomaly Detection** — IsolationForest runs every 5 minutes on per-IP feature vectors
- **Alert Storage** — Deduplication via time-bucketed `alert_key` + `IntegrityError` guard

### Detection Rules
| Rule | Trigger | Severity |
|---|---|---|
| BRUTE_FORCE_LOGIN | ≥5 failed logins from same IP in 10 min | HIGH |
| CREDENTIAL_STUFFING | >10 distinct users failed from same IP in 5 min | HIGH |
| REQUEST_FLOOD | >200 requests from same IP in 1 min | MEDIUM |
| ACCOUNT_TAKEOVER_SUSPECTED | Password change after login from different IP | HIGH |
| IMPOSSIBLE_TRAVEL | Same user logged in from 2 IPs within 10 min | HIGH |
| ADMIN_ACTION_BURST | Admin performs >5 high-impact actions in 5 min | HIGH |
| DATA_EXFILTRATION_SUSPECTED | Same actor exports data >3× in 10 min | CRITICAL |
| USER_AGENT_ROTATION | >10 distinct user-agents from same IP in 5 min | MEDIUM |
| HIGH_API_ERROR_RATE | Error rate >60% over ≥20 requests in 5 min | MEDIUM |
| BULK_DATA_ACCESS | Actor accesses >100 records in 10 min | HIGH |
| SERVICE_DOWNTIME_CASCADE | >5 services unavailable in 3 min | CRITICAL |
| DB_HEALTH_DEGRADATION | >20 DB errors in 2 min | HIGH |
| ML_TRAFFIC_ANOMALY | IsolationForest outlier on IP traffic features | MEDIUM |

### Threat Scoring Engine
Composite 0–100 risk score per IP / actor:
- Severity weights (CRITICAL=40, HIGH=25, MEDIUM=10, LOW=3)
- Logarithmic volume bonus (cap +20)
- Rule variety bonus — each unique rule adds +5 (cap +15)
- Recency amplifier — alerts in last 10 min multiply sub-score ×1.5
- ML anomaly flat bonus (+20)

Score is bucketed into **LOW / MEDIUM / HIGH / CRITICAL** tiers.

### Analytics Endpoints (chart-ready JSON)
| Endpoint | Chart type |
|---|---|
| `GET /analytics/summary` | KPI stat cards |
| `GET /analytics/alerts-over-time` | Line / area chart |
| `GET /analytics/severity-distribution` | Pie / donut chart |
| `GET /analytics/rule-breakdown` | Horizontal bar chart |
| `GET /analytics/hourly-heatmap` | Calendar heatmap (7×24 matrix) |
| `GET /analytics/top-ips` | Stacked bar chart |
| `GET /analytics/threat-score/ip/{ip}` | Single IP score |
| `GET /analytics/threat-score/actor/{id}` | Single actor score |
| `GET /analytics/threat-leaderboard/ips` | Ranked IP leaderboard |
| `GET /analytics/threat-leaderboard/actors` | Ranked actor leaderboard |

---

## Project Structure

```
app/
├── main.py                        # FastAPI app, lifespan, scheduler
├── core/
│   ├── config.py                  # Pydantic settings (DATABASE_URL)
│   └── enums.py                   # LogLevel, AlertSeverity enums
├── db/
│   └── database.py                # Engine (SQLite dev / PostgreSQL prod), session
├── models/
│   ├── log.py                     # Log ORM model
│   └── alerts.py                  # Alert ORM model
├── schemas/
│   ├── log_schema.py              # LogCreate, LogResponse
│   └── alert_schema.py            # AlertResponse
├── api/routes/
│   ├── logs.py                    # POST /logs, GET /logs
│   ├── alerts.py                  # GET /alerts
│   └── analytics.py               # GET /analytics/*
└── services/
│   ├── log_service.py             # Persist + trigger detection
│   ├── alert_service.py           # Alert queries
│   ├── detection_service.py       # 12 rule-based detectors
│   ├── event_normalizer.py        # Fuzzy event type normalization
│   ├── threat_scorer.py           # Composite threat scoring engine
│   └── analytics_service.py      # Chart-ready aggregation queries
└── ml/
    ├── feature_builder.py         # Per-IP feature vectors from DB
    ├── anomaly_detector.py        # IsolationForest wrapper
    └── ml_runner.py               # Orchestrates ML pipeline + alert creation
```

---

## Setup

```bash
# Dev (SQLite, zero config)
pip install fastapi uvicorn sqlalchemy pydantic-settings apscheduler scikit-learn pandas

uvicorn app.main:app --reload
# → http://localhost:8000/docs
```

```bash
# Production (PostgreSQL)
echo "DATABASE_URL=postgresql+psycopg2://user:pass@host/dbname" > .env
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The engine automatically switches between SQLite (WAL mode enabled) and PostgreSQL based on `DATABASE_URL`. No code changes needed.

---

## Example: Ingest a Log

```bash
curl -X POST http://localhost:8000/logs/ \
  -H "Content-Type: application/json" \
  -d '{
    "service": "auth-service",
    "event_type": "AUTH_LOGIN_FAILED",
    "level": "WARNING",
    "actor_id": "user_123",
    "ip_address": "1.2.3.4",
    "context": {"user_agent": "Mozilla/5.0"}
  }'
```

## Example: Get Threat Score for an IP

```bash
curl http://localhost:8000/analytics/threat-score/ip/1.2.3.4?window_hours=24
# → {"ip_address": "1.2.3.4", "score": 82.5, "tier": "CRITICAL", "alert_count": 7, ...}
```

## Example: Get Chart Data

```bash
curl "http://localhost:8000/analytics/alerts-over-time?hours=24&bucket_minutes=30"
# → {"labels": [...], "datasets": {"CRITICAL": [...], "HIGH": [...], ...}}
```
