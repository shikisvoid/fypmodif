"""
End-to-end proof script for EDR + ML integration.

What this script demonstrates:
1) ML component is active and can classify telemetry (direct /predict calls).
2) EDR-style telemetry ingestion path is active (/ingest/telemetry).
3) Detection pipeline consumes ingested telemetry and sends response actions
   visible via response-controller (/isolations).

Run (from HealthCareCenter root):
  python monitoring/demo_edr_ml_proof.py
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from urllib import request, error

import numpy as np
import pandas as pd


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "ml-engine", "data")

ML_PREDICT_URL = os.environ.get("ML_PREDICT_URL", "http://localhost:5000/predict")
INGEST_URL = os.environ.get("INGEST_URL", "http://localhost:9090/ingest/telemetry")
TELEMETRY_URL = os.environ.get("TELEMETRY_URL", "http://localhost:9090/telemetry")
ISOLATIONS_URL = os.environ.get("ISOLATIONS_URL", "http://localhost:4100/isolations")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def http_json(url, method="GET", payload=None, timeout=10):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url=url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        if not body:
            return {}
        return json.loads(body)


def pick_samples():
    parquet_files = [f for f in sorted(os.listdir(DATA_DIR)) if f.endswith(".parquet")]
    if not parquet_files:
        raise RuntimeError(f"No parquet files found in {DATA_DIR}")

    # Use first file with both benign and attack rows.
    for fname in parquet_files:
        fpath = os.path.join(DATA_DIR, fname)
        df = pd.read_parquet(fpath)
        if "Label" not in df.columns:
            continue
        benign = df[df["Label"] == "Benign"]
        attack = df[df["Label"] != "Benign"]
        if len(benign) > 0 and len(attack) > 0:
            return benign.reset_index(drop=True), attack.reset_index(drop=True), fname

    raise RuntimeError("Could not find a parquet file containing both benign and attack rows.")


def sanitize_ml_features(row):
    ml_features = {}
    for k, v in row.items():
        if k == "Label":
            continue
        if isinstance(v, (int, float, np.integer, np.floating)):
            fv = float(v)
            if np.isfinite(fv):
                ml_features[k] = fv
    return ml_features


def make_telemetry(host_id, role, email, ml_features):
    return {
        "hostId": host_id,
        "ts": now_iso(),
        "userRole": role,
        "userEmail": email,
        "source": "demo-edr-ml-proof",
        # Keep rule-trigger fields quiet to isolate ML contribution.
        "processes": [],
        "files": [],
        "network": {},
        "logs": [],
        "alerts": [],
        "ml_features": ml_features,
    }


def find_attack_that_ml_flags(attack_df, max_scan=200):
    """
    Try first N attack rows until ML returns anomaly=true.
    Falls back to first row if none are flagged in the scan window.
    """
    upper = min(max_scan, len(attack_df))
    fallback_payload = None
    fallback_pred = None

    for i in range(upper):
        row = attack_df.iloc[i]
        host_id = f"demo-attack-{uuid.uuid4().hex[:8]}"
        payload = make_telemetry(host_id, "doctor", "doctor@hospital.com", sanitize_ml_features(row))
        pred = http_json(ML_PREDICT_URL, method="POST", payload=payload)
        if fallback_payload is None:
            fallback_payload, fallback_pred = payload, pred
        if pred.get("is_anomaly"):
            return payload, pred, i

    return fallback_payload, fallback_pred, -1


def main():
    print("=== EDR + ML Proof Script ===")
    print(f"ML endpoint:         {ML_PREDICT_URL}")
    print(f"Ingestion endpoint:  {INGEST_URL}")
    print(f"Telemetry endpoint:  {TELEMETRY_URL}")
    print(f"Isolations endpoint: {ISOLATIONS_URL}")

    benign_df, attack_df, src_file = pick_samples()
    print(f"\nUsing data source: {src_file}")

    benign_host = f"demo-benign-{uuid.uuid4().hex[:8]}"

    benign_payload = make_telemetry(
        benign_host, "nurse", "nurse@hospital.com", sanitize_ml_features(benign_df.iloc[0])
    )
    attack_payload, attack_pred, found_idx = find_attack_that_ml_flags(attack_df)
    attack_host = attack_payload["hostId"]

    print("\n1) Direct ML predictions")
    benign_pred = http_json(ML_PREDICT_URL, method="POST", payload=benign_payload)
    print(f"  Benign host:  {benign_host}")
    print(
        f"    -> class={benign_pred.get('classification')} "
        f"is_anomaly={benign_pred.get('is_anomaly')} "
        f"score={benign_pred.get('anomaly_score')}"
    )
    print(f"  Attack host:  {attack_host}")
    print(
        f"    -> class={attack_pred.get('classification')} "
        f"is_anomaly={attack_pred.get('is_anomaly')} "
        f"score={attack_pred.get('anomaly_score')}"
    )
    if found_idx >= 0:
        print(f"    -> attack sample index used: {found_idx} (from scanned attack rows)")
    else:
        print("    -> no anomaly found in scan window; using first attack sample as fallback")

    print("\n2) Send EDR-style telemetry to ingestion")
    http_json(INGEST_URL, method="POST", payload=benign_payload)
    http_json(INGEST_URL, method="POST", payload=attack_payload)
    print("  Sent benign + attack telemetry to /ingest/telemetry")

    print("\n3) Verify telemetry reached collector")
    telemetry = http_json(TELEMETRY_URL, method="GET")
    recent = telemetry.get("recentTelemetry", [])
    seen_benign = any(x.get("hostId") == benign_host for x in recent)
    seen_attack = any(x.get("hostId") == attack_host for x in recent)
    print(f"  Benign in recent telemetry: {seen_benign}")
    print(f"  Attack in recent telemetry: {seen_attack}")

    print("\n4) Wait for monitor->controller pipeline (8s)")
    time.sleep(8)

    print("\n5) Check response-controller actions")
    isolations = http_json(ISOLATIONS_URL, method="GET")
    relevant = [
        x for x in isolations
        if x.get("hostId") in (benign_host, attack_host)
    ]
    if relevant:
        print(f"  Found {len(relevant)} relevant controller action(s):")
        for item in relevant[-5:]:
            print(
                f"    host={item.get('hostId')} action={item.get('action')} "
                f"reason={item.get('reason')} ts={item.get('ts')}"
            )
    else:
        print("  No controller actions found for demo hosts yet.")
        print("  This can happen if ML classified attack as non-malicious for this sample.")

    print("\n=== Summary ===")
    print(f"ML predicted benign host anomaly?  {bool(benign_pred.get('is_anomaly'))}")
    print(f"ML predicted attack host anomaly?  {bool(attack_pred.get('is_anomaly'))}")
    print(f"Telemetry ingestion confirmed?      {seen_benign and seen_attack}")
    print(f"Controller action observed?         {len(relevant) > 0}")
    print("\nIf needed, run again to sample different rows.")


if __name__ == "__main__":
    try:
        main()
    except error.URLError as e:
        print(f"Network error: {e}")
        print("Make sure docker services are up and ports 5000/9090/4100 are reachable.")
    except Exception as e:
        print(f"Error: {e}")
