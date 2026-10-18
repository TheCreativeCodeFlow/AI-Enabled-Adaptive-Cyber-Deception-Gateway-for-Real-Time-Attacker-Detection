#!/usr/bin/env python3
"""
Model training pipeline for Stage 3 Detection Service.
Generates reproducible synthetic training data, fits the anomaly detection
pipeline, evaluates basic metrics, and persists model.joblib.
"""

import os
import sys
from sklearn.metrics import classification_report, roc_auc_score

# Ensure detection package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.dataset import generate_synthetic_dataset
from src.ml_model import train_model, DEFAULT_MODEL_PATH


def main():
    print("[Training] Generating synthetic request features...")
    X_test, y_test = generate_synthetic_dataset(n_benign=500, n_anomaly=150, random_state=999)

    print(f"[Training] Fitting model pipeline to {DEFAULT_MODEL_PATH}...")
    pipeline = train_model(save_path=DEFAULT_MODEL_PATH)

    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    auc = roc_auc_score(y_test, y_prob)
    print("\n[Evaluation on Held-Out Synthetic Test Set]")
    print(f"ROC-AUC Score: {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Anomaly"]))

    print(f"[Training] Model successfully saved to: {DEFAULT_MODEL_PATH}")


if __name__ == "__main__":
    main()
