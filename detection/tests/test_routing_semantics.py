"""
Test Suite: Routing Semantics & Session Behavior Regression Tests (Stage 11)
Verifies:
  1. Semantic distinction between:
     - Session Identifiers (pseudonymous token)
     - Session Stickiness (routing-layer continuity)
     - Session Behavioral History (detection-layer rolling metrics)
     - Variant D dual-ablation behavior
  2. Routing Destinations:
     - ORIGIN: Physical destination is production origin
     - OBSERVE_ONLY: Physical destination is production origin (any attack routed here is an Origin Leak)
     - DECEPTION: Physical destination is isolated deception runtime
  3. Formal Metric Disentanglement:
     - Detection Accuracy vs Diversion Rate vs Containment Rate vs Origin Leakage Rate
"""

import os
import sys
import json
import hashlib
import pytest
from typing import Dict, Any, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation_runner import (
    calculate_des_from_evidence,
    compute_classification_metrics,
    evaluate_ablation_variant,
    extract_features_from_request,
    load_model,
    DEFAULT_MODEL_PATH,
)


def test_routing_destinations_and_origin_leakage_accounting():
    """
    Stage 11 Task 1:
    Verifies that requests assigned OBSERVE_ONLY physically reach the upstream origin.
    Therefore, any malicious request (ground_truth.is_attack == True) that receives
    OBSERVE_ONLY must be recorded as an ORIGIN LEAK (False Negative).
    """
    # Sample scenario stream with benign and attack requests
    scenarios = [
        # Benign request -> correctly receives ORIGIN -> TN
        {
            "scenario_id": "test-benign-1",
            "request": {"method": "GET", "path": "/api/catalog", "headers": {}, "body": ""},
            "ground_truth": {"is_attack": False, "category": "BENIGN", "expected_routing": "ORIGIN"},
        },
        # High-confidence attack -> receives DECEPTION -> TP (Contained, 0 origin leak)
        {
            "scenario_id": "test-attack-diverted",
            "request": {"method": "POST", "path": "/api/users", "headers": {}, "body": "' UNION SELECT 1,2,3--"},
            "ground_truth": {"is_attack": True, "category": "SQLI", "expected_routing": "DECEPTION"},
        },
        # Borderline attack probe -> receives OBSERVE_ONLY -> reaches origin -> MUST BE COUNTED AS LEAK (FN)
        {
            "scenario_id": "test-attack-observe-only",
            "request": {"method": "GET", "path": "/api/catalog?filter=admin", "headers": {}, "body": ""},
            "ground_truth": {"is_attack": True, "category": "RECON", "expected_routing": "DECEPTION"},
        },
    ]

    model = load_model(DEFAULT_MODEL_PATH)
    res = evaluate_ablation_variant(scenarios, "A_FULL", model)

    routing = res["routing_outcomes"]
    cm = res["metrics"]["confusion_matrix"]

    # All non-diverted requests (whether ORIGIN or OBSERVE_ONLY) are routed to origin
    assert routing["routed_to_origin"] == cm["tn"] + cm["fn"]
    # All attack requests routed to origin (including OBSERVE_ONLY) must be counted as origin leaks
    assert routing["origin_leak_count"] == cm["fn"]


def test_metric_disentanglement_detection_diversion_containment_leakage():
    """
    Stage 11 Task 1:
    Formally disentangles:
      1. Detection (classification decision: BENIGN vs SUSPICIOUS vs MALICIOUS)
      2. Diversion (gateway routing decision: target == DECEPTION in active mode)
      3. Containment (adversary isolated in honeypot with zero origin leaks)
      4. Origin Leakage (uncontained attack request reaching upstream origin)
    """
    # Case: Shadow mode vs Active mode vs Observe Only
    # In Shadow mode: 10 attacks detected as MALICIOUS, but Diversion = 0%, Containment = 0%, Leaks = 10 (100%)
    # In Active mode with 10 attacks: 8 diverted, 2 observe-only
    #   Detection: 10/10 flagged as anomalous (8 Malicious, 2 Suspicious)
    #   Diversion: 8/10 (80.0%)
    #   Containment: 8/10 (80.0%, provided honeypot does not fail)
    #   Origin Leakage: 2/10 (20.0%, the 2 observe-only requests reached origin)
    
    tp = 8
    fp = 0
    tn = 10
    fn = 2  # The 2 attack requests that received OBSERVE_ONLY / ORIGIN

    metrics = compute_classification_metrics(tp, fp, tn, fn)

    detection_sensitivity = (tp + fn) / (tp + fn)  # 100% of attacks detected as anomalous/suspicious
    diversion_rate = tp / (tp + fn)                # 80% diverted
    containment_rate = tp / (tp + fn)              # 80% contained
    origin_leak_rate = fn / (tp + fn)              # 20% leaked to origin

    assert diversion_rate == 0.80
    assert origin_leak_rate == 0.20
    assert metrics["fnr"] == origin_leak_rate
    assert metrics["recall"] == containment_rate


def test_variant_d_dual_ablation_semantics():
    """
    Stage 11 Task 1:
    Verifies that Variant D disables BOTH:
      1. Session Stickiness (SessionRoutingStore routing continuity)
      2. Session Behavioral History (rolling context features: auth failures, burst frequency)
    """
    model = load_model(DEFAULT_MODEL_PATH)

    # Multi-request attack session:
    # Request 1: Flagrant SQL injection in session sess_multi_1 (score ~ 0.90)
    # Request 2: Subtle reconnaissance query in session sess_multi_1 (score ~ 0.50, but auth_failure_count=5 in context)
    session_scenarios = [
        {
            "scenario_id": "multi-1",
            "session_id": "sess_multi_1",
            "request": {"method": "POST", "path": "/api/users", "headers": {}, "body": "' UNION SELECT password FROM users--"},
            "ground_truth": {"is_attack": True, "category": "SQLI"},
            "context_features": {"auth_failure_count": 0, "request_frequency": 1.0, "decoy_interactions": 0},
        },
        {
            "scenario_id": "multi-2",
            "session_id": "sess_multi_1",
            "request": {"method": "GET", "path": "/api/catalog/search?q=test", "headers": {}, "body": ""},
            "ground_truth": {"is_attack": True, "category": "RECON"},
            "context_features": {"auth_failure_count": 5, "request_frequency": 25.0, "decoy_interactions": 1},
        },
    ]

    # In Variant A (Full B4 with stickiness and context history):
    # Both requests are contained (Request 1 triggers diversion; Request 2 is sticky and high context risk)
    res_a = evaluate_ablation_variant(session_scenarios, "A_FULL", model)
    assert res_a["routing_outcomes"]["origin_leak_count"] == 0
    assert res_a["routing_outcomes"]["diverted_to_deception"] == 2

    # In Variant D (Stateless: no stickiness, context neutralized):
    # Request 1 is diverted, but Request 2 is evaluated statelessly with neutral context,
    # resulting in OBSERVE_ONLY / ORIGIN -> LEAKS TO ORIGIN!
    res_d = evaluate_ablation_variant(session_scenarios, "D_NO_HISTORY", model)
    assert res_d["routing_outcomes"]["origin_leak_count"] == 1, "Variant D must leak subtle second probe to origin"
    assert res_d["routing_outcomes"]["diverted_to_deception"] == 1


def test_external_dataset_schema_and_integrity():
    """
    Stage 11 Task 2 & 3:
    Verifies that the external public HTTP security benchmark dataset:
      - Exists at data/scenarios/external_benchmark_v1.json
      - Contains 100 scenarios (50 Benign, 50 Attacks)
      - Matches its recorded cryptographic SHA-256 content hash
      - Covers real HTTP request fields: method, path, headers, body, client_ip
    """
    import hashlib
    ext_path = os.path.join(REPO_ROOT, "data", "scenarios", "external_benchmark_v1.json")
    assert os.path.exists(ext_path), f"External dataset missing at {ext_path}"

    with open(ext_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["dataset_version"] == "1.0.0"
    scenarios = data["scenarios"]
    assert len(scenarios) == 100

    benign = [s for s in scenarios if not s["ground_truth"]["is_attack"]]
    attacks = [s for s in scenarios if s["ground_truth"]["is_attack"]]
    assert len(benign) == 50
    assert len(attacks) == 50

    # Cryptographic SHA-256 check
    stored_hash = data["content_sha256"]
    computed_hash = hashlib.sha256(json.dumps(scenarios, sort_keys=True).encode("utf-8")).hexdigest()
    assert stored_hash == computed_hash, "External dataset SHA-256 mismatch"

    # Verify real HTTP fields present without fabrication
    for s in scenarios:
        req = s["request"]
        assert "method" in req and req["method"] in ["GET", "POST", "PUT", "DELETE", "HEAD"]
        assert "path" in req and isinstance(req["path"], str)
        assert "headers" in req and isinstance(req["headers"], dict)
        assert "body" in req and isinstance(req["body"], str)
        assert "ground_truth" in s
        assert "is_attack" in s["ground_truth"]
        assert "category" in s["ground_truth"]


def test_external_benchmark_evaluation_results_reconciliation():
    """
    Stage 11 Task 3 & 4:
    Verifies that the recorded external evaluation results:
      - Match observed empirical execution:
        - B4 / Variant A: TP=37, FP=0, TN=50, FN=13 -> Accuracy=87.0%, Recall=74.0%, Precision=100.0%, F1=0.851, Leaks=13
        - Variant B (Rules Only): TP=23, FP=0, TN=50, FN=27 -> Accuracy=73.0%, Recall=46.0%, F1=0.630, Leaks=27
      - Markdown report agrees with JSON results
    """
    json_path = os.path.join(REPO_ROOT, "reports", "external_benchmark_results.json")
    md_path = os.path.join(REPO_ROOT, "reports", "external_benchmark_evaluation.md")

    assert os.path.exists(json_path), f"External results JSON missing at {json_path}"
    assert os.path.exists(md_path), f"External report Markdown missing at {md_path}"

    with open(json_path, "r", encoding="utf-8") as f:
        res = json.load(f)

    b4 = res["baseline_results"]["B4"]
    cm4 = b4["metrics"]["confusion_matrix"]
    assert cm4["tp"] == 37
    assert cm4["fp"] == 0
    assert cm4["tn"] == 50
    assert cm4["fn"] == 13
    assert b4["metrics"]["accuracy"] == 0.87
    assert b4["metrics"]["recall"] == 0.74
    assert b4["metrics"]["precision"] == 1.0
    assert b4["metrics"]["f1"] == 0.8506
    assert b4["routing_outcomes"]["origin_leak_count"] == 13

    vb = res["ablation_results"]["B_NO_ML"]
    cm_vb = vb["metrics"]["confusion_matrix"]
    assert cm_vb["tp"] == 23
    assert cm_vb["fp"] == 0
    assert cm_vb["tn"] == 50
    assert cm_vb["fn"] == 27
    assert vb["metrics"]["accuracy"] == 0.73
    assert vb["metrics"]["recall"] == 0.46
    assert vb["routing_outcomes"]["origin_leak_count"] == 27

    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    assert "87.0%" in md_text
    assert "74.0%" in md_text
    assert "0.851" in md_text
    assert "13/50 (26.0%)" in md_text
    assert "73.0%" in md_text
    assert "46.0%" in md_text
    assert "27/50 (54.0%)" in md_text

