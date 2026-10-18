import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.schemas import RequestFeatures
from src.deterministic import evaluate_deterministic_baseline
from src.ml_model import train_model, load_model


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    """
    1. Acceptance Test: GET /health returns valid healthy JSON.
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "detection"
    assert data["stage"] == "Stage 3 — ML Detection Engine"
    assert data["model_loaded"] is True
    assert "uptime" in data


def test_score_valid_request(client):
    """
    2. Acceptance Test: POST /score validates inputs and returns a risk score between 0 and 1.
    """
    payload = {
        "request_id": "test-uuid-001",
        "method": "GET",
        "path": "/api/users",
        "path_depth": 2,
        "path_length": 10,
        "path_entropy": 2.3,
        "has_suspicious_keywords": False,
        "suspicious_keyword_count": 0,
        "query_param_count": 1,
        "query_entropy": 1.2,
        "header_count": 8,
        "missing_expected_headers": [],
        "suspicious_header_patterns": [],
        "body_size": 0,
        "request_frequency": 1.2,
        "auth_failure_count": 0,
        "decoy_interactions": 0,
        "client_ip": "192.168.1.50",
    }
    response = client.post("/score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["request_id"] == "test-uuid-001"
    assert 0.0 <= data["risk_score"] <= 1.0
    assert data["classification"] in ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    assert 0.0 <= data["confidence"] <= 1.0
    assert len(data["evidence"]) > 0
    assert data["inference_duration_ms"] >= 0.0


def test_deterministic_baseline_reproducibility():
    """
    3. Acceptance Test: Identical inputs produce reproducible results for the deterministic baseline.
    """
    features = RequestFeatures(
        request_id="repro-1",
        method="POST",
        path="/admin/config.php",
        path_depth=2,
        path_length=17,
        path_entropy=3.8,
        has_suspicious_keywords=True,
        suspicious_keyword_count=2,
        query_param_count=0,
        query_entropy=0.0,
        header_count=5,
        missing_expected_headers=["user-agent"],
        suspicious_header_patterns=["sqlmap/1.5"],
        body_size=120,
        request_frequency=16.5,
        auth_failure_count=3,
        decoy_interactions=0,
    )

    score_1, evidence_1 = evaluate_deterministic_baseline(features)
    score_2, evidence_2 = evaluate_deterministic_baseline(features)
    score_3, evidence_3 = evaluate_deterministic_baseline(features)

    assert score_1 == score_2 == score_3
    assert evidence_1 == evidence_2 == evidence_3
    assert score_1 >= 0.70  # Highly anomalous indicators
    assert any("sqlmap" in ev for ev in evidence_1)


def test_malformed_input_rejection(client):
    """
    4. Acceptance Test: Invalid inputs receive controlled validation errors.
    """
    # Missing required request_id and path
    response = client.post("/score", json={"method": "GET"})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data

    # Invalid negative values for non-negative fields
    bad_payload = {
        "request_id": "test-bad",
        "path": "/test",
        "path_depth": -5,
    }
    response2 = client.post("/score", json=bad_payload)
    assert response2.status_code == 422


def test_synthetic_model_training_and_loading(tmp_path):
    """
    5. Acceptance Test: Synthetic model training and model loading work reproducibly.
    """
    model_file = str(tmp_path / "test_model.joblib")
    pipeline = train_model(save_path=model_file)
    assert pipeline is not None

    loaded_pipeline = load_model(model_path=model_file)
    assert loaded_pipeline is not None

    # Compare predictions
    features = RequestFeatures(
        request_id="test-load",
        path="/api/data",
        path_depth=2,
        path_length=9,
        path_entropy=2.1,
    )
    from src.ml_model import predict_anomaly_score

    score1, conf1 = predict_anomaly_score(pipeline, features)
    score2, conf2 = predict_anomaly_score(loaded_pipeline, features)

    assert score1 == score2
    assert conf1 == conf2


def test_benign_vs_malicious_scoring(client):
    """
    6. Verifies that benign requests score low and attack requests score high.
    """
    benign_payload = {
        "request_id": "benign-req",
        "method": "GET",
        "path": "/api/v1/items",
        "path_depth": 3,
        "path_length": 13,
        "path_entropy": 2.4,
        "has_suspicious_keywords": False,
        "suspicious_keyword_count": 0,
        "query_param_count": 1,
        "query_entropy": 1.0,
        "header_count": 10,
        "missing_expected_headers": [],
        "suspicious_header_patterns": [],
        "body_size": 0,
        "request_frequency": 1.0,
        "auth_failure_count": 0,
        "decoy_interactions": 0,
        "client_ip": "10.0.0.1",
    }
    res_benign = client.post("/score", json=benign_payload).json()
    assert res_benign["classification"] == "BENIGN"
    assert res_benign["risk_score"] < 0.35

    attack_payload = {
        "request_id": "attack-req",
        "method": "POST",
        "path": "/etc/passwd",
        "path_depth": 2,
        "path_length": 11,
        "path_entropy": 3.9,
        "has_suspicious_keywords": True,
        "suspicious_keyword_count": 3,
        "query_param_count": 2,
        "query_entropy": 3.2,
        "header_count": 3,
        "missing_expected_headers": ["user-agent", "accept"],
        "suspicious_header_patterns": ["nikto-scanner"],
        "body_size": 250,
        "request_frequency": 25.0,
        "auth_failure_count": 6,
        "decoy_interactions": 1,
        "client_ip": "203.0.113.19",
    }
    res_attack = client.post("/score", json=attack_payload).json()
    assert res_attack["classification"] in ["SUSPICIOUS", "MALICIOUS"]
    assert res_attack["risk_score"] > res_benign["risk_score"]
    assert len(res_attack["evidence"]) > 1
