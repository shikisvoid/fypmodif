"""
ML Intrusion Detection System - Real-Time Inference API (RF-only)
=================================================================
Flask microservice using Random Forest as primary detector.
"""

import os
import json
import numpy as np
import joblib
from flask import Flask, request, jsonify

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
PORT = int(os.environ.get('ML_PORT', 5000))

app = Flask(__name__)

rf_model = None
scaler = None
feature_config = None
FEATURE_NAMES = []
LOG_FEATURES = []
RF_THRESHOLD = 0.5


def load_model():
    """Load trained RF model, scaler, and feature config."""
    global rf_model, scaler, feature_config, FEATURE_NAMES, LOG_FEATURES, RF_THRESHOLD

    config_path = os.path.join(MODEL_DIR, 'feature_config.json')
    rf_path = os.path.join(MODEL_DIR, 'random_forest.pkl')
    scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')

    if not os.path.exists(config_path):
        print('[ML] WARNING: feature_config.json not found. Run train.py first.')
        return False

    with open(config_path, 'r') as f:
        feature_config = json.load(f)

    FEATURE_NAMES = feature_config['features']
    LOG_FEATURES = feature_config.get('log_transform_features', [])
    RF_THRESHOLD = float(feature_config.get('rf_threshold', 0.5))

    if not os.path.exists(scaler_path):
        print('[ML] WARNING: scaler.pkl not found. Run train.py first.')
        return False
    scaler = joblib.load(scaler_path)

    if not os.path.exists(rf_path):
        print('[ML] WARNING: random_forest.pkl not found. Run train.py first.')
        return False
    rf_model = joblib.load(rf_path)

    print(f'[ML] RF loaded. Features={len(FEATURE_NAMES)} threshold={RF_THRESHOLD:.3f}')
    return True


def extract_features(telemetry):
    """
    Extract CIC-IDS2018-compatible features from telemetry.
    Missing values default to 0.
    """
    features = {f: 0.0 for f in FEATURE_NAMES}

    ml_features = telemetry.get('ml_features', {})
    if ml_features:
        for key, val in ml_features.items():
            if key in features:
                try:
                    features[key] = float(val)
                except (ValueError, TypeError):
                    pass

    net = telemetry.get('network', telemetry.get('net', {}))
    if isinstance(net, list):
        net = net[0] if net else {}

    procs = telemetry.get('processes', [])
    files = telemetry.get('files', [])
    logs = telemetry.get('logs', [])

    def set_if_zero(key, val):
        if features.get(key, 0.0) == 0.0:
            features[key] = float(val)

    if isinstance(procs, list):
        set_if_zero('Total Fwd Packets', len(procs))
    if isinstance(files, list):
        set_if_zero('Total Backward Packets', len(files))

    if isinstance(net, dict):
        set_if_zero('Flow Bytes/s', net.get('bytes_sent', net.get('bytesSent', 0)))
        set_if_zero('Flow Packets/s', net.get('packets_per_sec', net.get('connRate', 0)))
        set_if_zero('Flow Duration', net.get('duration', net.get('sessionDuration', 0)))
        set_if_zero('Fwd Packets Length Total', net.get('bytes_sent', net.get('bytesSent', 0)))
        set_if_zero('Bwd Packets Length Total', net.get('bytes_recv', net.get('bytesRecv', 0)))
        set_if_zero('Fwd Header Length', net.get('header_bytes', 0))
        set_if_zero('Bwd Header Length', net.get('resp_header_bytes', 0))
        set_if_zero('Avg Packet Size', net.get('avg_packet_size', 0))
        set_if_zero('Fwd Packet Length Mean', net.get('fwd_pkt_mean', 0))
        set_if_zero('Bwd Packet Length Mean', net.get('bwd_pkt_mean', 0))

    security_events = len(logs) if isinstance(logs, list) else 0
    set_if_zero('SYN Flag Count', security_events)

    db = telemetry.get('dbActivity', {})
    if isinstance(db, dict):
        db_alerts = db.get('alerts', [])
        set_if_zero('RST Flag Count', len(db_alerts) if isinstance(db_alerts, list) else 0)
        set_if_zero('FIN Flag Count', db.get('activeQueries', 0))

    susp_files = sum(1 for f in files if isinstance(f, dict) and f.get('type') == 'SUSPICIOUS_FILE') if isinstance(files, list) else 0
    set_if_zero('PSH Flag Count', susp_files)
    set_if_zero('ACK Flag Count', len(procs if isinstance(procs, list) else []) + len(files if isinstance(files, list) else []) + security_events)

    for f in LOG_FEATURES:
        if f in features:
            features[f] = float(np.log1p(max(features[f], 0.0)))

    return np.array([[features[f] for f in FEATURE_NAMES]])


@app.route('/predict', methods=['POST'])
def predict():
    if rf_model is None:
        return jsonify({'error': 'Model not loaded'}), 503

    try:
        telemetry = request.get_json(force=True)
        features = extract_features(telemetry)
        features_scaled = scaler.transform(features)

        rf_proba = float(rf_model.predict_proba(features_scaled)[0][1])
        rf_pred = int(rf_proba >= RF_THRESHOLD)

        if rf_pred == 1:
            classification = 'Malicious'
            action = 'block'
            confidence = rf_proba
        else:
            classification = 'Normal'
            action = 'allow'
            confidence = 1.0 - rf_proba

        result = {
            'anomaly_score': round(rf_proba, 6),
            'is_anomaly': bool(rf_pred),
            'classification': classification,
            'action': action,
            'confidence': round(confidence, 4),
            'hostId': telemetry.get('hostId', 'unknown'),
            'userRole': telemetry.get('userRole', 'unknown'),
            'userEmail': telemetry.get('userEmail', 'unknown'),
            'model_scores': {
                'random_forest_proba': round(rf_proba, 6),
                'random_forest_pred': rf_pred,
                'random_forest_threshold': round(RF_THRESHOLD, 6),
            },
            'ensemble_mode': False,
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy' if rf_model is not None else 'model_not_loaded',
        'rf_loaded': rf_model is not None,
        'if_loaded': False,
        'ensemble_mode': False,
        'features': len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        'rf_threshold': RF_THRESHOLD if rf_model is not None else None,
    })


if __name__ == '__main__':
    print('[ML] Starting ML Intrusion Detection System (RF-only)...')
    loaded = load_model()
    if not loaded:
        print('[ML] WARNING: Starting without models. Train first with: python train.py')
    app.run(host='0.0.0.0', port=PORT, debug=False)
