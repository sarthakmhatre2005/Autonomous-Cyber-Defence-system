"""
Offline training script for the system's telemetry-derived dataset.

Safety constraint:
This training is offline only. It does NOT affect real-time detection/blocking.
"""

from __future__ import annotations

import json
import os
from typing import Any
from collections import Counter

import joblib
from sklearn.compose import ColumnTransformer
from sklearn.metrics import confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
import csv
import numpy as np


def load_dataset_rows(csv_path: str) -> list[dict[str, Any]]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset CSV not found: {csv_path}")
    rows: list[dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def train(csv_path: str | None = None, out_dir: str | None = None) -> dict[str, Any]:
    if csv_path is None:
        csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "training_dataset.csv")
        csv_path = os.path.abspath(csv_path)
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(__file__), "artifacts")
        out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    all_rows = load_dataset_rows(csv_path)

    # Filter clean labels only: label in {0,1}
    clean_rows = []
    for r in all_rows:
        try:
            lbl = int(float(r.get("label", "-1")))
        except Exception:
            lbl = -1
        if lbl in (0, 1):
            r["label"] = lbl
            clean_rows.append(r)

    if not clean_rows:
        raise RuntimeError("No clean labels (0/1) found. Refuse to train.")

    # Basic preprocessing lists
    categorical_cols = ["protocol_mode", "process_name_mode", "source_type"]

    behavior_features = [
        "anomaly_score_mean",
        "threat_score_mean",
        "event_count_60",
        "request_rate_60",
        "unique_ports_60",
        "port_entropy_60",
        "burst_score_10",
        "interarrival_variance_10",
        "time_since_prev_seen",
    ]

    system_features = [
        "repeat_count_max",
        "total_flags",
        "past_blocks",
    ]

    # For compatibility with existing dataset columns
    extra_numeric = [
        "anomaly_score_max",
        "event_count_10",
        "request_rate_10",
        "last_seen_age",
    ]

    numeric_cols_all = behavior_features + system_features + extra_numeric

    feature_order = categorical_cols + numeric_cols_all
    n_cat = len(categorical_cols)
    n_total = len(feature_order)

    X = []
    y = []
    for r in clean_rows:
        feat: list[Any] = []
        for c in categorical_cols:
            feat.append(r.get(c, "unknown"))
        for c in numeric_cols_all:
            try:
                feat.append(float(r.get(c, 0.0)))
            except Exception:
                feat.append(0.0)
        X.append(feat)
        y.append(int(r["label"]))

    X = np.array(X, dtype=object)
    y = np.array(y, dtype=int)

    # Label distribution diagnostics
    print("Label distribution:", Counter(y.tolist()))
    positive_rate = float(np.mean(y))
    print("Positive rate:", positive_rate)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    categorical_idx = list(range(n_cat))

    # Index lookup for numeric features inside X (after categoricals)
    idx_map = {col: n_cat + i for i, col in enumerate(numeric_cols_all)}

    numeric_idx_behavior = [idx_map[c] for c in behavior_features]
    numeric_idx_behavior_system = [idx_map[c] for c in behavior_features + system_features]

    def train_one_model(numeric_idx: list[int], suffix: str) -> tuple[dict[str, float], str]:
        preprocessor = ColumnTransformer(
            transformers=[
                ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_idx),
                ("num", StandardScaler(), numeric_idx),
            ]
        )

        clf = LogisticRegression(max_iter=400, class_weight="balanced", random_state=42)
        model = Pipeline(steps=[("preprocess", preprocessor), ("clf", clf)])

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall = float(recall_score(y_test, y_pred, zero_division=0))

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        metrics_local = {
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
        }

        model_path_local = os.path.join(out_dir, f"telemetry_malicious_model_{suffix}.joblib")
        joblib.dump(model, model_path_local)

        return metrics_local, model_path_local

    # Model A: behavior-only features
    metrics_a, model_path_a = train_one_model(numeric_idx_behavior, "behavior")
    # Model B: behavior + system-derived features
    metrics_b, model_path_b = train_one_model(numeric_idx_behavior_system, "behavior_system")

    metrics = {
        "behavior_only": metrics_a,
        "behavior_plus_system": metrics_b,
        "test_size": len(y_test),
        "train_size": len(y_train),
        "positive_rate_train": float(np.mean(y_train)),
        "positive_rate_test": float(np.mean(y_test)),
    }

    metrics_path = os.path.join(out_dir, "training_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return {
        "model_behavior_path": model_path_a,
        "model_behavior_system_path": model_path_b,
        "metrics_path": metrics_path,
        "metrics": metrics,
    }


if __name__ == "__main__":
    result = train()
    print("Training complete.")
    print(json.dumps(result["metrics"], indent=2))

