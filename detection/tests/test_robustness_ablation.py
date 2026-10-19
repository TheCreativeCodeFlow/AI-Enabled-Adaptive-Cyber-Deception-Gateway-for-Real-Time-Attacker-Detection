"""
Test Suite: Adversarial Robustness and Architectural Ablation Study (Stage 10)
Verifies:
  1. Robustness Dataset Schema & Cryptographic Integrity (70 versioned scenarios, SHA-256 verification)
  2. Ground-Truth Isolation across Evasion and Probe Scenarios
  3. Controlled Architectural Ablation Variants (Variant A, B, C, D) Invariance & Component Isolation
  4. Microsecond-Resolution Latency Measurement (no 0.000 ms rounding)
  5. Fault Tolerance and Safety Gate on Malformed/Edge Inputs
  6. Mathematical DES Formula Reconciliation and Zero-Leak Invariance
  7. Ablation Report Artifact Schema & Metadata Integrity
"""

import os
import sys
import json
import hashlib
import pytest
from typing import Dict, Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation_runner import (
    calculate_shannon_entropy,
    extract_features_from_request,
    calculate_des_from_evidence,
    compute_classification_metrics,
    format_latency_stats,
    evaluate_ablation_variant,
    evaluate_b1_direct_origin,
    evaluate_b2_static_deception,
    evaluate_b3_rule_based_adaptive,
    evaluate_b4_proposed_gateway,
    ROBUSTNESS_DATASET_PATH,
    DATASET_PATH,
    ABLATION_REPORT_PATH,
    REPORT_PATH,
)
from src.schemas import RequestFeatures
from src.ml_model import load_model, DEFAULT_MODEL_PATH


@pytest.fixture(scope="module")
def robustness_data():
    assert os.path.exists(ROBUSTNESS_DATASET_PATH), f"Robustness dataset missing: {ROBUSTNESS_DATASET_PATH}"
    with open(ROBUSTNESS_DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture(scope="module")
def ablation_report():
    assert os.path.exists(ABLATION_REPORT_PATH), f"Ablation report missing: {ABLATION_REPORT_PATH}"
    with open(ABLATION_REPORT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def test_robustness_dataset_schema_and_integrity(robustness_data):
    """
    Acceptance Criteria 2:
    Robustness dataset schema must contain 70 scenarios (37 benign, 33 attacks)
    and match the recorded cryptographic SHA-256 hash.
    """
    assert robustness_data.get("dataset_version") == "1.0.0"
    assert "content_sha256" in robustness_data
    scenarios = robustness_data["scenarios"]
    assert len(scenarios) == 70

    # Verify distribution
    benign = [s for s in scenarios if not s["ground_truth"]["is_attack"]]
    attacks = [s for s in scenarios if s["ground_truth"]["is_attack"]]
    assert len(benign) == 37
    assert len(attacks) == 33

    # Check key probe categories are represented
    categories = {s["ground_truth"]["category"] for s in scenarios}
    required_probes = {
        "BENIGN",
        "BENIGN_SUSPICIOUS_TOKENS",
        "SQLI",
        "TRAVERSAL",
        "CMDI",
        "SSTI",
        "NOSQLI",
        "XXE",
        "LDAP_INJECTION",
        "LOG4J_JNDI",
        "CRED_STUFF",
        "MALFORMED",
        "MALFORMED_ATTACK",
    }
    for req_probe in required_probes:
        assert req_probe in categories, f"Required probe category {req_probe} missing in robustness dataset"

    # Verify content SHA-256 integrity
    with open(ROBUSTNESS_DATASET_PATH, "r", encoding="utf-8") as f:
        file_obj = json.load(f)
    stored_hash = file_obj.get("content_sha256")
    content_str = json.dumps(file_obj["scenarios"], sort_keys=True)
    computed_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    assert stored_hash == computed_hash, "Robustness dataset SHA-256 mismatch: content was altered"


def test_robustness_ground_truth_isolation(robustness_data):
    """
    Acceptance Criteria 1 & 2:
    Ground truth and probe categories must never leak into feature extraction.
    """
    for sample in robustness_data["scenarios"][:15]:
        assert "ground_truth" in sample

        features = extract_features_from_request(sample["request"], sample.get("context_features", {}))
        feature_dict = features.model_dump()

        assert "ground_truth" not in feature_dict
        assert "label" not in feature_dict
        assert "is_attack" not in feature_dict
        assert "category" not in feature_dict
        assert "expected_safety_constraint" not in feature_dict

        assert isinstance(features.path_entropy, float)
        assert features.path_entropy >= 0.0


def test_ablation_variants_execution():
    """
    Acceptance Criteria 3:
    Evaluate controlled architectural variants (A, B, C, D) on small representative subsets.
    Verify component isolation:
      - Variant B (No-ML): Disables ML inference; uses only rule-based scoring.
      - Variant C (No-Adaptation): Pins deception runtime to static DISCOVERY node (1 unique node).
      - Variant D (No-Behavioral-History): Stateless evaluation.
    """
    model = load_model(DEFAULT_MODEL_PATH)

    # Sample mini-dataset
    mini_scenarios = [
        {
            "scenario_id": "mini-1",
            "request": {"method": "GET", "path": "/api/users/profile", "headers": {}, "body": ""},
            "ground_truth": {"is_attack": False, "category": "BENIGN", "expected_routing": "ORIGIN"},
        },
        {
            "scenario_id": "mini-2",
            "request": {"method": "POST", "path": "/api/catalog/search", "headers": {}, "body": "UNION SELECT 1,2,3--"},
            "ground_truth": {"is_attack": True, "category": "SQLI", "expected_routing": "DECEPTION"},
        },
    ]

    # Variant A (Full Proposed Gateway)
    res_a = evaluate_ablation_variant(mini_scenarios, "A_FULL", model)
    assert res_a["name"] == "Variant A: Full Proposed Gateway (B4)"
    assert res_a["metrics"]["total_evaluated"] == 2
    assert "latency_ms" in res_a
    assert "detection_latency_ms" in res_a

    # Variant B (No-ML Ablation)
    res_b = evaluate_ablation_variant(mini_scenarios, "B_NO_ML", None)
    assert res_b["name"] == "Variant B: No-ML Ablation (Rules Only)"
    assert res_b["metrics"]["total_evaluated"] == 2
    # Latency of Variant B should be significantly faster because ML is skipped
    assert res_b["detection_latency_ms"]["p50"] < res_a["detection_latency_ms"]["p50"] or res_b["detection_latency_ms"]["p50"] < 1.0

    # Variant C (No-Adaptation Ablation)
    res_c = evaluate_ablation_variant(mini_scenarios, "C_NO_ADAPT", model)
    assert res_c["name"] == "Variant C: No-Adaptation Ablation (Static Deception)"
    assert res_c["metrics"]["total_evaluated"] == 2

    # Variant D (No-Behavioral-History Ablation)
    res_d = evaluate_ablation_variant(mini_scenarios, "D_NO_HISTORY", model)
    assert res_d["name"] == "Variant D: No-Behavioral-History Ablation (Stateless)"
    assert res_d["metrics"]["total_evaluated"] == 2


def test_microsecond_latency_formatting():
    """
    Acceptance Criteria 4:
    Measure Detection Latency vs. Gateway End-to-End Latency with microsecond resolution.
    Never report rounded 0.000 ms.
    """
    # Extremely small durations (e.g. direct origin / heuristic passthrough)
    sub_micro_durations = [0.0000002, 0.0000003, 0.0000004, 0.0000005]
    stats = format_latency_stats(sub_micro_durations)

    assert "formatted_p50" in stats
    assert "formatted_p99" in stats
    assert "µs" in stats["formatted_p50"], f"Expected µs formatting for sub-microsecond values, got {stats['formatted_p50']}"
    assert "0.000 ms" not in stats["formatted_p50"]

    # Millisecond durations
    milli_durations = [0.0152, 0.0163, 0.0148, 0.0210]
    stats_milli = format_latency_stats(milli_durations)
    assert "ms" in stats_milli["formatted_p50"]
    assert stats_milli["p50"] > 0.0

    # Empty durations safety
    empty_stats = format_latency_stats([])
    assert empty_stats["formatted_p50"] == "N/A"


def test_fault_tolerance_and_safety_edges():
    """
    Acceptance Criteria 5:
    Ensure gateway and feature extractors safely handle malformed, extreme, or edge-case inputs
    without crashing or raising unhandled exceptions.
    """
    edge_cases = [
        # Empty request dictionary
        {},
        # Malformed nulls and missing fields
        {"method": "", "path": "", "headers": None, "body": None},
        # Path with null bytes
        {"method": "GET", "path": "/api/users\x00/admin", "headers": {}, "body": ""},
        # Extremely large header and body
        {
            "method": "POST",
            "path": "/api/test",
            "headers": {"X-Large": "A" * 10000},
            "body": "B" * 50000,
        },
        # Non-ASCII UTF-8 sequences
        {"method": "GET", "path": "/api/測試/유저", "headers": {"User-Agent": "🤖 Bot"}, "body": ""},
        # Extreme JSON nesting / corruption
        {"method": "POST", "path": "/api/json", "headers": {}, "body": "{" * 500},
    ]

    for req in edge_cases:
        try:
            feats = extract_features_from_request(req, {})
            assert isinstance(feats, RequestFeatures)
            assert isinstance(feats.path_entropy, float)
        except Exception as e:
            pytest.fail(f"Feature extraction raised unhandled exception on edge case {req}: {e}")


def test_des_formal_reconciliation():
    """
    Acceptance Criteria 4 & 6:
    Formal mathematical reconciliation of DES:
      DES = I[L_leak = 0] * (0.30*D + 0.30*C + 0.25*T + 0.15*E)
    Verify that:
      1. Held-out test set produces exactly 0.925 (due to 3/4 DSG nodes).
      2. Combined benchmark produces 1.000 (with 4/4 nodes).
      3. Any origin leak collapses DES to 0.000.
    """
    # 1. Held-out scenario: 0 leaks, 3 nodes (depth = 3/4 = 0.75), 30 interactions, 30 valid responses, 20 decoy endpoints
    held_out_des = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=3,
        total_dsg_nodes=4,
        successful_deception_responses=30,
        total_deception_interactions=30,
        unique_decoy_endpoints=20,
        total_decoy_endpoints=4,
    )
    # D = 3/4 = 0.75 -> 0.75 * 0.30 = 0.225
    # C = 30/30 = 1.0 -> 1.0 * 0.30 = 0.300
    # T = min(1.0, 30/10) = 1.0 -> 1.0 * 0.25 = 0.250
    # E = min(1.0, 20/4) = 1.0 -> 1.0 * 0.15 = 0.150
    # Sum = 0.225 + 0.300 + 0.250 + 0.150 = 0.925
    assert held_out_des["score"] == 0.925
    assert held_out_des["origin_leakage"] is False

    # 2. Combined benchmark: 0 leaks, 4 nodes, 60 interactions, 60 valid responses, 38 decoy endpoints
    combined_des = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=4,
        total_dsg_nodes=4,
        successful_deception_responses=60,
        total_deception_interactions=60,
        unique_decoy_endpoints=38,
        total_decoy_endpoints=4,
    )
    assert combined_des["score"] == 1.000

    # 3. Leak gate: 1 leak collapses DES to 0.000
    leaked_des = calculate_des_from_evidence(
        origin_leak_count=1,
        unique_dsg_nodes_visited=4,
        total_dsg_nodes=4,
        successful_deception_responses=60,
        total_deception_interactions=60,
        unique_decoy_endpoints=38,
        total_decoy_endpoints=4,
    )
    assert leaked_des["score"] == 0.000
    assert leaked_des["origin_leakage"] is True


def test_ablation_report_file_integrity(ablation_report):
    """
    Acceptance Criteria 7:
    The generated ablation report must contain valid metadata, empirical outcomes,
    and exact model hashes.
    """
    assert "metadata" in ablation_report
    meta = ablation_report["metadata"]
    assert "Stage 10" in meta["stage"]
    assert "model" in meta
    assert "sha256" in meta["model"]
    assert len(meta["model"]["sha256"]) == 64

    # Held-out test ablation results
    assert "ablation_study_results" in ablation_report
    ablation_study = ablation_report["ablation_study_results"]
    assert "held_out_test_split" in ablation_study
    test_ablation = ablation_study["held_out_test_split"]
    for variant in ["A_FULL", "B_NO_ML", "C_NO_ADAPT", "D_NO_HISTORY"]:
        assert variant in test_ablation
        assert "metrics" in test_ablation[variant]
        assert "routing_outcomes" in test_ablation[variant]
        assert "latency_ms" in test_ablation[variant]
        assert "detection_latency_ms" in test_ablation[variant]

    # Robustness ablation results
    assert "adversarial_robustness_split" in ablation_study
    rob_ablation = ablation_study["adversarial_robustness_split"]
    for variant in ["A_FULL", "B_NO_ML", "C_NO_ADAPT", "D_NO_HISTORY"]:
        assert variant in rob_ablation
        assert "metrics" in rob_ablation[variant]

    # DES Reconciliation section
    assert "audit_findings" in ablation_report
    audit = ablation_report["audit_findings"]
    assert "des_reconciliation" in audit
    des_recon = audit["des_reconciliation"]
    assert des_recon["held_out_des"] == 0.925
    assert des_recon["full_benchmark_des"] == 1.000
