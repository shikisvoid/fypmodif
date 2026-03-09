# Phase 2 Testing Guide - EDR + ML Proof

## Objective
Provide concrete, repeatable evidence that:
1. EDR agents are collecting and sending telemetry.
2. ML engine is actively classifying telemetry.
3. Detection pipeline and response controller are connected.

This file does **not** replace `PHASE2-TESTING-GUIDE.md`.

---

## Implemented Components (Proof Scope)

### EDR Agents
- Real agent: `agents/real-edr/agent.js`
- Role middleware: `agents/real-edr/role-edr-middleware.js`
- 8 role-specific containers (in `docker-compose.sdp.yml`):
  - `edr-admin`, `edr-doctor`, `edr-nurse`, `edr-receptionist`
  - `edr-lab-technician`, `edr-pharmacist`, `edr-accountant`, `edr-patient`

### Telemetry Ingestion
- `monitoring/metrics-exporter.js`
- Endpoints:
  - `POST /ingest/telemetry`
  - `GET /telemetry`
  - `GET /metrics`

### ML Engine (RF-only)
- Inference service: `ml-engine/app.py`
- Endpoint: `POST /predict`
- Model artifacts:
  - `ml-engine/models/random_forest.pkl`
  - `ml-engine/models/scaler.pkl`
  - `ml-engine/models/feature_config.json`

### Detection + Response
- Rule/ML orchestrator: `monitoring/traffic-analyzer.js`
- Response controller: `response/controller/index.js`
- Endpoints:
  - `POST /alert`
  - `GET /isolations`
  - `POST /action/revert`

---

## Quick End-to-End Proof (Single Command)

Use this script:
- `monitoring/demo_edr_ml_proof.py`

### Step 1: Start services
```powershell
cd "C:\Users\HP\Desktop\PHASE1\PHASE1\PHASE1\HealthCareCenter"
docker compose -f docker-compose.sdp.yml up -d
Start-Sleep -Seconds 60
docker compose -f docker-compose.sdp.yml ps
```

### Step 2: Run proof
```powershell
python monitoring\demo_edr_ml_proof.py
```

### Expected output evidence
- Direct ML prediction for benign + attack telemetry
- Telemetry ingestion confirmation (`/ingest/telemetry` -> `/telemetry`)
- Response action visibility from `/isolations` when triggered
- Final summary booleans:
  - `Telemetry ingestion confirmed? True`
  - `ML predicted attack host anomaly? ...`
  - `Controller action observed? ...`

---

## Manual Proof Commands (Viva-Friendly)

### 1) Prove role EDR containers are running
```powershell
docker ps --format "table {{.Names}}\t{{.Status}}" | findstr edr-
```

Expected: 8 `edr-*` containers visible and `Up`.

### 2) Prove telemetry is being ingested
```powershell
curl.exe http://localhost:9090/telemetry
```

Expected: JSON with `recentTelemetry` entries containing `hostId`, `userRole`, `userEmail`, `processes`, `network`, `logs`.

### 3) Prove ML service is active
```powershell
curl.exe http://localhost:5000/health
```

Expected: `rf_loaded: true`, `ensemble_mode: false`, `features` count, `rf_threshold`.

### 4) Prove ML predicts on telemetry payload
```powershell
curl.exe -X POST http://localhost:5000/predict -H "Content-Type: application/json" -d "{\"hostId\":\"demo-host\",\"userRole\":\"doctor\",\"userEmail\":\"doctor@hospital.com\",\"ml_features\":{}}"
```

Expected: JSON with:
- `classification`
- `action`
- `anomaly_score`
- `model_scores.random_forest_proba`

### 5) Prove response controller stores actions
```powershell
curl.exe http://localhost:4100/isolations
```

Expected: action records (`isolate`, `restrict`, `revoke_tokens`, etc.) after alerts are triggered.

---

## Deterministic Controller Trigger (Optional)

If you need guaranteed response evidence during demo:

```powershell
Invoke-WebRequest -Uri "http://localhost:4100/alert" -Method POST -ContentType "application/json" -UseBasicParsing -Body '{
  "severity": "CRITICAL",
  "event": "EXFILTRATION",
  "hostId": "demo-critical-host",
  "ts": "2026-02-28T12:00:00Z",
  "details": { "dst": "8.8.8.8", "port": 443, "userEmail": "doctor@hospital.com", "userRole": "doctor" }
}'
```

Then:
```powershell
curl.exe http://localhost:4100/isolations
```

Expected: entry with `hostId: "demo-critical-host"` and containment action.

---

## ML Contribution Statement (For Teacher)

Yes, ML contributes to anomaly detection:
- `traffic-analyzer.js` calls ML `/predict` for telemetry items.
- ML anomalies are translated into alerts (`ML_ANOMALY` / correlated cases).
- Response controller receives these alerts via `/alert`.

So the chain is:
`EDR telemetry -> ingestion -> ML inference + rules -> alert -> response actions`.

---

## Current Model Results (Saved Artifact)

From `ml-engine/models/training_metrics.json`:
- Recall: `95.30%`
- Precision: `73.80%`
- F1-score: `83.18%`
- FPR: `8.43%`
- ROC-AUC: `0.9871`

These are generated from actual local training runs and persisted in artifact files.

