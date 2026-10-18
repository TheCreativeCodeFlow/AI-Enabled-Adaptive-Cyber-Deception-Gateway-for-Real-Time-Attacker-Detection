import os
import joblib
import numpy as np
from typing import Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from .schemas import RequestFeatures
from .dataset import generate_synthetic_dataset

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model.joblib"
)


def features_to_vector(features: RequestFeatures) -> np.ndarray:
    """
    Transforms a RequestFeatures object into a numerical feature vector.
    """
    return np.array([[
        float(features.path_depth),
        float(features.path_length),
        float(features.path_entropy),
        float(features.suspicious_keyword_count),
        float(features.query_param_count),
        float(features.query_entropy),
        float(features.header_count),
        float(len(features.missing_expected_headers)),
        float(len(features.suspicious_header_patterns)),
        float(features.body_size),
        float(features.request_frequency),
        float(features.auth_failure_count),
        float(features.decoy_interactions),
    ]])


def train_model(save_path: str = DEFAULT_MODEL_PATH) -> Pipeline:
    """
    Trains an explainable ensemble classifier on the synthetic baseline dataset.
    Saves and returns the serialized scikit-learn pipeline.
    """
    X_train, y_train = generate_synthetic_dataset(
        n_benign=2000, n_anomaly=500, random_state=42
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X_train, y_train)

    # Save to disk
    joblib.dump(pipeline, save_path)
    return pipeline


def load_model(model_path: str = DEFAULT_MODEL_PATH) -> Pipeline:
    """
    Loads serialized model pipeline from disk; if absent, automatically trains
    and persists a new baseline model.
    """
    if os.path.exists(model_path):
        try:
            return joblib.load(model_path)
        except Exception:
            # Fall back to retraining if corrupted
            return train_model(model_path)
    return train_model(model_path)


def predict_anomaly_score(
    model: Pipeline, features: RequestFeatures
) -> Tuple[float, float]:
    """
    Predicts probability of anomalous/malicious traffic pattern.
    Returns:
        (anomaly_score, confidence)
        Both bounded in [0.0, 1.0].
    """
    try:
        vec = features_to_vector(features)
        # Class 1 is anomaly
        probs = model.predict_proba(vec)[0]
        anomaly_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        # Confidence is distance from decision boundary (0.5) scaled to [0.5, 1.0]
        confidence = float(0.5 + abs(anomaly_prob - 0.5))
        return round(max(0.0, min(1.0, anomaly_prob)), 4), round(confidence, 4)
    except Exception as err:
        # Graceful fallback on feature or model errors
        return 0.0, 0.5
