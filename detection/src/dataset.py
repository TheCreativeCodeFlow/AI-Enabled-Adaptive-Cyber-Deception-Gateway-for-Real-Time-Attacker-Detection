import numpy as np
from typing import Tuple

FEATURE_NAMES = [
    "path_depth",
    "path_length",
    "path_entropy",
    "suspicious_keyword_count",
    "query_param_count",
    "query_entropy",
    "header_count",
    "missing_headers_count",
    "suspicious_headers_count",
    "body_size",
    "request_frequency",
    "auth_failure_count",
    "decoy_interactions",
]


def generate_synthetic_dataset(
    n_benign: int = 2000, n_anomaly: int = 500, random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates synthetic feature matrices for training and evaluation.
    Labels: 0 = Benign, 1 = Anomaly

    Note: Synthetic data models baseline feature distributions and does not
    claim to match production attack diversity.
    """
    rng = np.random.RandomState(random_state)

    # 1. Benign Samples (label 0)
    b_path_depth = rng.randint(1, 5, size=n_benign)
    b_path_length = rng.randint(5, 40, size=n_benign)
    b_path_entropy = rng.normal(2.5, 0.4, size=n_benign).clip(1.0, 3.8)
    b_suspicious_keywords = np.zeros(n_benign, dtype=int)
    b_query_param_count = rng.poisson(lam=1.0, size=n_benign).clip(0, 5)
    b_query_entropy = rng.normal(1.5, 0.5, size=n_benign).clip(0.0, 3.0)
    b_header_count = rng.randint(6, 16, size=n_benign)
    b_missing_headers = np.zeros(n_benign, dtype=int)
    b_suspicious_headers = np.zeros(n_benign, dtype=int)
    b_body_size = rng.exponential(scale=200, size=n_benign).clip(0, 5000)
    b_request_freq = rng.exponential(scale=1.5, size=n_benign).clip(0.1, 6.0)
    b_auth_failures = np.zeros(n_benign, dtype=int)
    b_decoy_interactions = np.zeros(n_benign, dtype=int)

    X_benign = np.column_stack([
        b_path_depth,
        b_path_length,
        b_path_entropy,
        b_suspicious_keywords,
        b_query_param_count,
        b_query_entropy,
        b_header_count,
        b_missing_headers,
        b_suspicious_headers,
        b_body_size,
        b_request_freq,
        b_auth_failures,
        b_decoy_interactions,
    ])
    y_benign = np.zeros(n_benign, dtype=int)

    # 2. Anomaly Samples (label 1)
    a_path_depth = rng.randint(2, 9, size=n_anomaly)
    a_path_length = rng.randint(25, 120, size=n_anomaly)
    a_path_entropy = rng.normal(4.2, 0.5, size=n_anomaly).clip(3.5, 5.5)
    a_suspicious_keywords = rng.randint(1, 5, size=n_anomaly)
    a_query_param_count = rng.randint(1, 10, size=n_anomaly)
    a_query_entropy = rng.normal(3.8, 0.6, size=n_anomaly).clip(2.5, 5.0)
    a_header_count = rng.randint(1, 7, size=n_anomaly)
    a_missing_headers = rng.randint(1, 4, size=n_anomaly)
    a_suspicious_headers = rng.randint(1, 3, size=n_anomaly)
    a_body_size = rng.exponential(scale=1500, size=n_anomaly).clip(0, 100000)
    a_request_freq = rng.uniform(8.0, 40.0, size=n_anomaly)
    a_auth_failures = rng.randint(0, 8, size=n_anomaly)
    a_decoy_interactions = rng.binomial(1, 0.3, size=n_anomaly)

    X_anomaly = np.column_stack([
        a_path_depth,
        a_path_length,
        a_path_entropy,
        a_suspicious_keywords,
        a_query_param_count,
        a_query_entropy,
        a_header_count,
        a_missing_headers,
        a_suspicious_headers,
        a_body_size,
        a_request_freq,
        a_auth_failures,
        a_decoy_interactions,
    ])
    y_anomaly = np.ones(n_anomaly, dtype=int)

    X = np.vstack([X_benign, X_anomaly])
    y = np.hstack([y_benign, y_anomaly])

    # Shuffle synchronously
    indices = rng.permutation(len(y))
    return X[indices], y[indices]
