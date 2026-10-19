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

    # 2. Anomaly Samples (label 1) across diverse attack modalities
    anomaly_samples = []
    n_per_mod = n_anomaly // 5

    # 2.1 Web Exploit Probes (keywords, path/query entropy, normal frequency)
    for _ in range(n_per_mod):
        anomaly_samples.append([
            rng.randint(2, 6),
            rng.randint(20, 90),
            rng.normal(3.8, 0.4),
            rng.randint(1, 5),
            rng.randint(1, 8),
            rng.normal(3.5, 0.5),
            rng.randint(6, 14),
            0,
            0,
            rng.exponential(300),
            rng.uniform(1.0, 5.0),
            0,
            0,
        ])

    # 2.2 Scanner & Reconnaissance Tools (suspicious/missing headers, elevated frequency)
    for _ in range(n_per_mod):
        anomaly_samples.append([
            rng.randint(1, 5),
            rng.randint(10, 50),
            rng.normal(3.0, 0.4),
            rng.randint(0, 2),
            rng.randint(0, 3),
            rng.normal(2.0, 0.4),
            rng.randint(1, 6),
            rng.randint(1, 4),
            rng.randint(1, 3),
            0,
            rng.uniform(10.0, 40.0),
            0,
            0,
        ])

    # 2.3 Credential Stuffing & Auth Abuse (auth failures, high frequency)
    for _ in range(n_per_mod):
        anomaly_samples.append([
            2,
            15,
            2.5,
            rng.randint(0, 1),
            0,
            0.0,
            rng.randint(6, 12),
            0,
            0,
            rng.randint(50, 300),
            rng.uniform(10.0, 35.0),
            rng.randint(3, 10),
            0,
        ])

    # 2.4 Decoy & Honeypot Probing (decoy interactions recorded)
    for _ in range(n_per_mod):
        anomaly_samples.append([
            rng.randint(2, 5),
            rng.randint(15, 60),
            rng.normal(3.2, 0.4),
            rng.randint(0, 2),
            rng.randint(0, 3),
            rng.normal(2.0, 0.5),
            rng.randint(5, 12),
            0,
            0,
            rng.exponential(200),
            rng.uniform(1.0, 10.0),
            0,
            rng.randint(1, 4),
        ])

    # 2.5 Composite & Obfuscated Attacks
    for _ in range(n_anomaly - len(anomaly_samples)):
        anomaly_samples.append([
            rng.randint(3, 8),
            rng.randint(40, 120),
            rng.normal(4.2, 0.5),
            rng.randint(2, 6),
            rng.randint(2, 8),
            rng.normal(4.0, 0.5),
            rng.randint(2, 7),
            rng.randint(1, 3),
            rng.randint(1, 3),
            rng.exponential(2000),
            rng.uniform(12.0, 45.0),
            rng.randint(1, 5),
            rng.binomial(1, 0.5),
        ])

    X_anomaly = np.array(anomaly_samples)
    y_anomaly = np.ones(n_anomaly, dtype=int)

    X = np.vstack([X_benign, X_anomaly])
    y = np.hstack([y_benign, y_anomaly])

    # Shuffle synchronously
    indices = rng.permutation(len(y))
    return X[indices], y[indices]
