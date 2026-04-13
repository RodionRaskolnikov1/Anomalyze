# 🚨 Anomalyze

**AI-Powered Log Anomaly Detection System**

---

## 🧠 Overview

**Anomalyze** is a backend-driven anomaly detection system designed to identify suspicious behavior in application logs using machine learning.

It simulates real-world security scenarios such as:

* Brute force login attacks
* API scraping bots
* Data exfiltration attempts
* Off-hours suspicious activity

The system processes logs, builds behavioral features per IP, and detects anomalies using an **Isolation Forest model**.

---

## 🔑 Live Demo
**Swagger UI:** https://anomalyze-5ayj.onrender.com/docs

Click **Authorize 🔒** and enter your API key to test all endpoints.

> Free tier — may take ~30s to wake up on first visit.

---

## ⚙️ Tech Stack

* **Backend:** FastAPI
* **Database:** SQLite (SQLAlchemy ORM)
* **Machine Learning:** Scikit-learn (Isolation Forest)
* **Data Processing:** Pandas
* **Environment:** Python 3.x

---

## 🏗️ Architecture

```
app/
├── api/              # API routes
├── core/             # Config, security
├── db/               # Database setup
├── models/           # DB models
├── ml/               # ML pipeline
│   ├── feature_builder.py
│   ├── trainer.py
│   ├── anomaly_detector.py
│   └── model_store.py
├── services/         # Business logic
└── main.py           # Entry point

scripts/
├── seed.py           # Generate synthetic logs
├── run_training.py   # Train ML model
└── verify.py         # Validate pipeline
```

---

## 🚀 Features

### 🔹 Log Simulation

* Generates realistic system activity
* Includes both normal and malicious patterns

### 🔹 Feature Engineering

* Aggregates logs per IP
* Extracts:

  * Request count
  * Failed login ratio
  * Error rate
  * Off-hours activity

### 🔹 Machine Learning

* Uses **Isolation Forest** for anomaly detection
* Automatically flags suspicious IPs

### 🔹 Model Persistence

* Saves trained models for reuse
* Prevents retraining on every run

### 🔹 Verification Pipeline

* Ensures:

  * Data availability
  * Model existence
  * Inference correctness

---

## 🧪 How It Works

1. **Seed Data**

   ```
   python -m app.scripts.seed
   ```

2. **Train Model**

   ```
   python -m app.scripts.run_training
   ```

3. **Verify Pipeline**

   ```
   python -m app.scripts.verify
   ```

4. **Run Server**

   ```
   uvicorn app.main:app --reload
   ```

---

## 📊 Example Output

* Detects anomalous IPs based on:

  * High request bursts
  * Suspicious login patterns
  * Unusual access timing

---

## 🔐 Security Simulation

| Attack Type      | Behavior                               |
| ---------------- | -------------------------------------- |
| Brute Force      | Repeated login failures                |
| Scraper          | High API volume + rotating user agents |
| Exfiltration     | Bulk data access & exports             |
| Off-hours Access | Activity during unusual hours          |

---

## ⚠️ Limitations

* Uses synthetic data (not production logs)
* Limited feature depth
* No real-time streaming (batch-based)

---

## 📈 Future Improvements

* Real-time log ingestion (Kafka / streaming)
* Advanced feature engineering (time-series behavior)
* Dashboard for visualization
* Model evaluation metrics (precision, recall)
* Role-based API security

---

## 👨‍💻 Author

Built as a learning-focused project to explore:

* Backend system design
* Machine learning integration
* Security analytics concepts

---

## ⭐ Why This Project Matters

This project demonstrates:

* End-to-end ML pipeline integration
* Clean backend architecture
* Real-world problem simulation

---

> “Not just detecting anomalies — understanding behavior.”
