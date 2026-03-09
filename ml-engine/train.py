"""
ML-Based Intrusion Detection System - Training Pipeline (RF-only)
=================================================================
Random Forest IDS using CSE-CIC-IDS2018 dataset.

Target: >97% attack recall, <3% FPR, >0.99 ROC-AUC
"""

import os
import time
import json
import warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_auc_score, precision_recall_fscore_support
import joblib

warnings.filterwarnings('ignore', category=FutureWarning)

# Configuration
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

RANDOM_STATE = 42

LOG_TRANSFORM_FEATURES = [
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
    'Total Fwd Packets', 'Total Backward Packets',
    'Avg Packet Size', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Fwd Packets Length Total', 'Bwd Packets Length Total',
    'Fwd IAT Total', 'Bwd IAT Total', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Fwd IAT Mean', 'Fwd IAT Std', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Fwd Header Length', 'Bwd Header Length',
    'Packet Length Variance', 'Active Mean', 'Active Std',
    'Idle Mean', 'Idle Std',
]

CORR_THRESHOLD = 0.95
TOP_K_FEATURES = 35

RF_N_ESTIMATORS = 500
RF_MAX_DEPTH = None
RF_MIN_SAMPLES_LEAF = 2

# Operating targets (user-defined)
TARGET_RECALL = 0.95
TARGET_FPR = 0.10
TARGET_PRECISION = 0.70
TARGET_F1 = 0.80
TARGET_AUC = 0.98

MAX_TOTAL_SAMPLES = 1_500_000


def load_dataset():
    print("=" * 70)
    print("  STEP 1: Loading CSE-CIC-IDS2018 Dataset")
    print("=" * 70)

    file_info = []
    label_counts = {}
    total_rows = 0
    for fname in sorted(os.listdir(DATA_DIR)):
        if not fname.endswith('.parquet'):
            continue
        fpath = os.path.join(DATA_DIR, fname)
        df = pd.read_parquet(fpath, columns=['Label'])
        n = len(df)
        total_rows += n
        for lbl, cnt in df['Label'].value_counts().items():
            label_counts[lbl] = label_counts.get(lbl, 0) + cnt
        file_info.append((fname, fpath, n))
        print(f"  {fname}: {n:,} rows")
        del df

    sample_frac = min(1.0, MAX_TOTAL_SAMPLES / total_rows)
    print(f"\n  Total available: {total_rows:,} rows")
    if sample_frac < 1.0:
        print(f"  Subsampling {sample_frac*100:.1f}% per file to stay under {MAX_TOTAL_SAMPLES:,}")

    benign_frames = []
    attack_frames = []

    for fname, fpath, _ in file_info:
        df = pd.read_parquet(fpath)
        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=RANDOM_STATE)

        is_benign = df['Label'] == 'Benign'
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

        b = df.loc[is_benign, numeric_cols].astype(np.float32)
        a = df.loc[~is_benign, numeric_cols].astype(np.float32)
        benign_frames.append(b)
        attack_frames.append(a)
        print(f"  Loaded {fname}: benign={len(b):,} attack={len(a):,}")
        del df, b, a

    X_benign = pd.concat(benign_frames, ignore_index=True)
    X_attack = pd.concat(attack_frames, ignore_index=True)
    del benign_frames, attack_frames

    print(f"\n  Sampled total: {len(X_benign) + len(X_attack):,}")
    print(f"  Benign: {len(X_benign):,} | Attack: {len(X_attack):,}")

    print("\n  Full dataset label distribution:")
    for lbl, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"    {lbl}: {cnt:,} ({cnt/total_rows*100:.2f}%)")

    return X_benign, X_attack


def clean_data(X_benign, X_attack):
    print("\n" + "=" * 70)
    print("  STEP 2: Data Cleaning")
    print("=" * 70)

    X = pd.concat([X_benign, X_attack], ignore_index=True)
    y = np.concatenate([
        np.zeros(len(X_benign), dtype=np.int8),
        np.ones(len(X_attack), dtype=np.int8),
    ])
    del X_benign, X_attack

    print(f"  Numeric features: {X.shape[1]}")

    n_bad = 0
    for col in X.columns:
        arr = X[col].values
        mask = np.isinf(arr) | np.isnan(arr)
        n_col_bad = int(mask.sum())
        n_bad += n_col_bad
        if n_col_bad > 0:
            arr[mask] = np.nan
            med = float(np.nanmedian(arr))
            arr[np.isnan(arr)] = med
            X[col] = arr
    print(f"  Replaced {n_bad:,} inf/NaN values with column medians")

    const_cols = [c for c in X.columns if X[c].nunique() <= 1]
    if const_cols:
        X = X.drop(columns=const_cols)
        print(f"  Removed {len(const_cols)} constant columns: {const_cols}")

    print(f"  Final shape: {X.shape} | Benign: {int((y==0).sum()):,} | Attack: {int((y==1).sum()):,}")
    return X, y


def engineer_features(X, y):
    print("\n" + "=" * 70)
    print("  STEP 3: Feature Engineering")
    print("=" * 70)

    log_applied = []
    for col in LOG_TRANSFORM_FEATURES:
        if col in X.columns:
            X[col] = np.log1p(X[col].clip(lower=0))
            log_applied.append(col)
    print(f"  Applied log1p to {len(log_applied)} skewed features")

    print(f"  Computing correlation matrix ({X.shape[1]} features)...")
    corr = X.corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    drop_cols = set()
    for col in upper.columns:
        correlated = upper.index[upper[col] > CORR_THRESHOLD].tolist()
        if correlated:
            drop_cols.add(col)
    if drop_cols:
        X = X.drop(columns=list(drop_cols))
        print(f"  Pruned {len(drop_cols)} highly correlated features (r>{CORR_THRESHOLD})")
    else:
        print(f"  No features above correlation threshold {CORR_THRESHOLD}")
    print(f"  Features after correlation pruning: {X.shape[1]}")

    print("  Training quick RF for feature importance ranking...")
    n_sample = min(200_000, len(X))
    idx = np.random.RandomState(RANDOM_STATE).choice(len(X), n_sample, replace=False)
    X_sub = X.iloc[idx]
    y_sub = y[idx]

    quick_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        class_weight='balanced',
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    quick_rf.fit(X_sub, y_sub)

    importances = pd.Series(quick_rf.feature_importances_, index=X.columns).sort_values(ascending=False)
    n_select = min(TOP_K_FEATURES, len(importances))
    selected = importances.head(n_select).index.tolist()
    X = X[selected]

    print(f"\n  Top {n_select} features by importance:")
    for i, (feat, imp) in enumerate(importances.head(n_select).items()):
        print(f"    {i+1:2d}. {feat}: {imp:.4f}")

    del quick_rf, X_sub, y_sub
    return X, selected, importances


def split_data(X, y):
    print("\n" + "=" * 70)
    print("  STEP 4: Stratified Train/Val/Test Split (70/15/15)")
    print("=" * 70)

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )

    for name, yy in [('Train', y_train), ('Val', y_val), ('Test', y_test)]:
        n = len(yy)
        n_atk = int(yy.sum())
        print(f"  {name:5s}: {n:>10,} samples | Benign: {n - n_atk:>10,} | Attack: {n_atk:>10,} ({n_atk/n*100:.1f}%)")

    return X_train, X_val, X_test, y_train, y_val, y_test


def train_random_forest(X_train, y_train, X_val, y_val):
    print("\n" + "=" * 70)
    print("  STEP 5: Training Random Forest")
    print("=" * 70)

    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc = scaler.transform(X_val)

    rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        class_weight='balanced',
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=0,
    )

    print(f"  Config: n_estimators={RF_N_ESTIMATORS}, max_depth={RF_MAX_DEPTH}, min_samples_leaf={RF_MIN_SAMPLES_LEAF}")
    print(f"  Training on {len(X_train_sc):,} samples...")
    t0 = time.time()
    rf.fit(X_train_sc, y_train)
    print(f"  Training completed in {time.time() - t0:.1f}s")

    y_val_proba = rf.predict_proba(X_val_sc)[:, 1]
    y_val_pred = (y_val_proba >= 0.5).astype(int)
    p, r, f1, _ = precision_recall_fscore_support(y_val, y_val_pred, average='binary')
    auc = roc_auc_score(y_val, y_val_proba)
    print(f"\n  Validation @0.50: Precision={p:.4f} Recall={r:.4f} F1={f1:.4f} AUC={auc:.4f}")

    print("\n  Optimizing threshold for target profile...")
    candidates = []
    for t in np.arange(0.01, 0.80, 0.01):
        y_t = (y_val_proba >= t).astype(int)
        tn_t, fp_t, fn_t, tp_t = confusion_matrix(y_val, y_t).ravel()
        recall_t = tp_t / (tp_t + fn_t) if (tp_t + fn_t) > 0 else 0.0
        fpr_t = fp_t / (fp_t + tn_t) if (fp_t + tn_t) > 0 else 0.0
        precision_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) > 0 else 0.0
        f1_t = 2 * tp_t / (2 * tp_t + fp_t + fn_t) if (2 * tp_t + fp_t + fn_t) > 0 else 0.0
        candidates.append((float(t), recall_t, fpr_t, precision_t, f1_t))

    feasible = [
        c for c in candidates
        if c[1] >= TARGET_RECALL and c[2] <= TARGET_FPR and c[3] >= TARGET_PRECISION and c[4] >= TARGET_F1
    ]
    if feasible:
        best = max(feasible, key=lambda c: (c[4], c[1], c[3], -c[2], -c[0]))
        status = 'target-met'
    else:
        def penalty(c):
            _, rec, fpr, prec, f1v = c
            return (
                4.0 * max(0.0, TARGET_RECALL - rec) +
                3.0 * max(0.0, fpr - TARGET_FPR) +
                2.0 * max(0.0, TARGET_PRECISION - prec) +
                2.0 * max(0.0, TARGET_F1 - f1v)
            )
        best = min(candidates, key=lambda c: (penalty(c), -c[4], -c[1], -c[3], c[2], -c[0]))
        status = 'fallback (closest-to-targets)'

    best_threshold = best[0]
    print(f"  Threshold search status: {status}")

    y_opt = (y_val_proba >= best_threshold).astype(int)
    p2, r2, f12, _ = precision_recall_fscore_support(y_val, y_opt, average='binary')
    tn2, fp2, fn2, tp2 = confusion_matrix(y_val, y_opt).ravel()
    fpr2 = fp2 / (fp2 + tn2) if (fp2 + tn2) > 0 else 0.0
    print(f"  Optimal threshold: {best_threshold:.2f}")
    print(f"  Validation @{best_threshold:.2f}: Precision={p2:.4f} Recall={r2:.4f} F1={f12:.4f} FPR={fpr2:.4f}")

    return rf, scaler, best_threshold


def evaluate_rf(rf, scaler, X_test, y_test, rf_threshold=0.5):
    print("\n" + "=" * 70)
    print(f"  STEP 6: Random Forest Evaluation on Test Set (threshold={rf_threshold:.2f})")
    print("=" * 70)

    X_test_sc = scaler.transform(X_test)
    rf_proba = rf.predict_proba(X_test_sc)[:, 1]
    rf_pred = (rf_proba >= rf_threshold).astype(int)

    p, r, f1, _ = precision_recall_fscore_support(y_test, rf_pred, average='binary')
    tn, fp, fn, tp = confusion_matrix(y_test, rf_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    auc = roc_auc_score(y_test, rf_proba)

    print(f"  Recall:     {r:.4f}  {'[OK]' if r >= TARGET_RECALL else '[MISS]'} (target >= {TARGET_RECALL:.2f})")
    print(f"  Precision:  {p:.4f}  {'[OK]' if p >= TARGET_PRECISION else '[MISS]'} (target >= {TARGET_PRECISION:.2f})")
    print(f"  F1-score:   {f1:.4f}  {'[OK]' if f1 >= TARGET_F1 else '[MISS]'} (target >= {TARGET_F1:.2f})")
    print(f"  ROC-AUC:    {auc:.4f}  {'[OK]' if auc >= TARGET_AUC else '[WARN]'} (target >= {TARGET_AUC:.2f})")
    print(f"  FPR:        {fpr:.4f}  {'[OK]' if fpr <= TARGET_FPR else '[WARN]'} (target <= {TARGET_FPR:.2f})")
    print(f"  Confusion:  TP={tp:,} TN={tn:,} FP={fp:,} FN={fn:,}")

    return {
        'model': 'Random Forest',
        'rf_threshold': round(float(rf_threshold), 4),
        'precision': round(float(p), 4),
        'recall': round(float(r), 4),
        'f1_score': round(float(f1), 4),
        'roc_auc': round(float(auc), 4),
        'false_positive_rate': round(float(fpr), 4),
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'test_samples': len(y_test),
        'attack_recall_pct': round(float(r) * 100, 2),
        'benign_correct_pct': round(float(tn) / (tn + fp) * 100, 2) if (tn + fp) > 0 else 0,
    }


def save_artifacts(rf, scaler, metrics, feature_names, importances, rf_threshold):
    print("\n" + "=" * 70)
    print("  STEP 7: Saving Artifacts")
    print("=" * 70)

    joblib.dump(rf, os.path.join(MODEL_DIR, 'random_forest.pkl'))
    print("  Saved: random_forest.pkl")
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    print("  Saved: scaler.pkl")

    with open(os.path.join(MODEL_DIR, 'training_metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)
    print("  Saved: training_metrics.json")

    config = {
        'features': feature_names,
        'n_features': len(feature_names),
        'log_transform_features': [f for f in LOG_TRANSFORM_FEATURES if f in feature_names],
        'rf_threshold': round(float(rf_threshold), 4),
        'rf_n_estimators': RF_N_ESTIMATORS,
        'rf_max_depth': RF_MAX_DEPTH,
        'corr_threshold': CORR_THRESHOLD,
        'feature_importances': {f: round(float(v), 6) for f, v in importances.head(len(feature_names)).items()},
        'trained_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'dataset': 'CSE-CIC-IDS2018',
    }
    with open(os.path.join(MODEL_DIR, 'feature_config.json'), 'w') as f:
        json.dump(config, f, indent=2)
    print("  Saved: feature_config.json")


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  ML-Based Intrusion Detection System - RF Training Pipeline")
    print("  Dataset: CSE-CIC-IDS2018 | Model: Random Forest")
    print("=" * 70)
    t_start = time.time()

    X_benign, X_attack = load_dataset()
    X, y = clean_data(X_benign, X_attack)
    del X_benign, X_attack

    X, selected_features, importances = engineer_features(X, y)
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X.values, y)
    del X

    rf, scaler, rf_threshold = train_random_forest(X_train, y_train, X_val, y_val)
    metrics = evaluate_rf(rf, scaler, X_test, y_test, rf_threshold=rf_threshold)
    save_artifacts(rf, scaler, metrics, selected_features, importances, rf_threshold)

    elapsed = time.time() - t_start
    print(f"\n{'=' * 70}")
    print(f"  TRAINING COMPLETE in {elapsed:.1f}s")
    print(f"  Attack Recall: {metrics['recall']*100:.2f}%  (target >= {TARGET_RECALL*100:.0f}%)")
    print(f"  Precision:     {metrics['precision']*100:.2f}%  (target >= {TARGET_PRECISION*100:.0f}%)")
    print(f"  F1-score:      {metrics['f1_score']*100:.2f}%  (target >= {TARGET_F1*100:.0f}%)")
    print(f"  FPR:           {metrics['false_positive_rate']*100:.2f}%  (target <= {TARGET_FPR*100:.0f}%)")
    print(f"  ROC-AUC:       {metrics['roc_auc']:.4f}  (target >= {TARGET_AUC:.2f})")
    print(f"{'=' * 70}\n")
