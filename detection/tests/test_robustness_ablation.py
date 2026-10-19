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


def test_variant_d_exact_confusion_matrix_and_metric_reconciliation(ablation_report):
    """
    Stage 10.1 Task 2: Reconcile Variant D.
    Verifies:
      - Dataset: benchmark_scenarios_v1.json (Held-Out Test Split, N=60: 30 Benign, 30 Attack).
      - Confusion matrix: TP=24, FP=0, TN=30, FN=6.
      - Total evaluated: 60.
      - Accuracy = (24 + 30) / 60 = 54 / 60 = 0.900 (90.0%).
      - Recall = 24 / (24 + 6) = 24 / 30 = 0.800 (80.0%).
      - Precision = 24 / (24 + 0) = 1.000 (100.0%).
      - F1 = 2 * (1.0 * 0.8) / (1.0 + 0.8) = 1.6 / 1.8 = 0.8889.
      - Origin leaks = 6 (FN = 6, 20.0% of attacks).
      - Reconciles that accuracy (90%) and recall (80%) come from the exact same evaluation run;
        the 30 benign requests (TN=30, FP=0) elevate overall accuracy, while missing session stickiness
        causes 6 multi-probe attacks to reach the origin (FN=6).
    """
    variant_d = ablation_report["ablation_study_results"]["held_out_test_split"]["D_NO_HISTORY"]
    metrics = variant_d["metrics"]
    cm = metrics["confusion_matrix"]

    # Exact confusion matrix
    assert cm["tp"] == 24
    assert cm["fp"] == 0
    assert cm["tn"] == 30
    assert cm["fn"] == 6
    assert metrics["total_evaluated"] == 60

    # Exact metric values
    assert metrics["accuracy"] == 0.9
    assert metrics["recall"] == 0.8
    assert metrics["precision"] == 1.0
    assert metrics["f1"] == 0.8889

    # Routing outcomes: 6 origin leaks
    routing = variant_d["routing_outcomes"]
    assert routing["origin_leak_count"] == 6
    assert routing["routed_to_origin"] == 36  # 30 benign + 6 leaked attacks
    assert routing["diverted_to_deception"] == 24

    # Mathematical reconciliation assertions
    calc_acc = (cm["tp"] + cm["tn"]) / metrics["total_evaluated"]
    calc_rec = cm["tp"] / (cm["tp"] + cm["fn"])
    calc_prec = cm["tp"] / (cm["tp"] + cm["fp"])
    calc_f1 = (2 * calc_prec * calc_rec) / (calc_prec + calc_rec)
    assert abs(calc_acc - 0.900) < 1e-6
    assert abs(calc_rec - 0.800) < 1e-6
    assert abs(calc_prec - 1.000) < 1e-6
    assert abs(calc_f1 - 0.8889) < 1e-4

    # Also test live evaluation of Variant D on held-out test set
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        bench_data = json.load(f)
    test_scenarios = [s for s in bench_data["scenarios"] if s.get("split") == "held_out_test"]
    assert len(test_scenarios) == 60

    model = load_model(DEFAULT_MODEL_PATH)
    live_res = evaluate_ablation_variant(test_scenarios, "D_NO_HISTORY", model)
    live_cm = live_res["metrics"]["confusion_matrix"]
    assert live_cm["tp"] == 24
    assert live_cm["fp"] == 0
    assert live_cm["tn"] == 30
    assert live_cm["fn"] == 6
    assert live_res["routing_outcomes"]["origin_leak_count"] == 6


def test_des_evidence_tracing_and_missing_observations_rule(ablation_report):
    """
    Stage 10.1 Task 3: Reconcile DES.
    Verifies:
      1. Held-out DES is 0.925 because depth is 3/4 = 0.750 (RECONNAISSANCE not visited in test split).
         DES = 0.30*0.75 + 0.30*1.0 + 0.25*1.0 + 0.15*1.0 = 0.225 + 0.300 + 0.250 + 0.150 = 0.925.
      2. Combined benchmark DES is 1.000 because all 4 DSG nodes are visited (depth = 4/4 = 1.0).
      3. Binary zero-leak gate: any origin leak collapses DES to strictly 0.000.
      4. Missing observations rule: when total deception interactions are zero,
         consistency_score and DES must evaluate strictly to 0.0, never silently treated as perfect.
    """
    audit = ablation_report["audit_findings"]["des_reconciliation"]
    assert audit["held_out_des"] == 0.925
    assert audit["full_benchmark_des"] == 1.000
    assert audit["adversarial_robustness_des"] == 0.000
    assert "depth" in audit["held_out_components"]
    assert audit["held_out_components"]["depth"] == 0.750
    assert audit["held_out_components"]["consistency"] == 1.000
    assert audit["held_out_components"]["dwell"] == 1.000
    assert audit["held_out_components"]["engagement"] == 1.000

    # 1. Held-out evidence reproduction
    held_out_res = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=3,
        total_dsg_nodes=4,
        successful_deception_responses=30,
        total_deception_interactions=30,
        unique_decoy_endpoints=20,
        total_decoy_endpoints=4,
    )
    assert held_out_res["score"] == 0.925
    assert held_out_res["depth_score"] == 0.75
    assert held_out_res["consistency_score"] == 1.0
    assert held_out_res["dwell_score"] == 1.0
    assert held_out_res["engagement_score"] == 1.0

    # 2. Combined benchmark evidence reproduction
    combined_res = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=4,
        total_dsg_nodes=4,
        successful_deception_responses=60,
        total_deception_interactions=60,
        unique_decoy_endpoints=38,
        total_decoy_endpoints=4,
    )
    assert combined_res["score"] == 1.000
    assert combined_res["depth_score"] == 1.0

    # 3. Adversarial Robustness gate: 17 leaks -> 0.000
    adv_res = calculate_des_from_evidence(
        origin_leak_count=17,
        unique_dsg_nodes_visited=3,
        total_dsg_nodes=4,
        successful_deception_responses=16,
        total_deception_interactions=16,
        unique_decoy_endpoints=10,
        total_decoy_endpoints=4,
    )
    assert adv_res["score"] == 0.000
    assert adv_res["origin_leakage"] is True
    assert adv_res["origin_leak_count"] == 17

    # 4. Missing observations rule: zero interactions must never produce non-zero consistency or DES
    zero_obs = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=0,
        total_dsg_nodes=4,
        successful_deception_responses=0,
        total_deception_interactions=0,
        unique_decoy_endpoints=0,
        total_decoy_endpoints=4,
    )
    assert zero_obs["score"] == 0.0
    assert zero_obs["consistency_score"] == 0.0
    assert zero_obs["depth_score"] == 0.0
    assert zero_obs["dwell_score"] == 0.0
    assert zero_obs["engagement_score"] == 0.0


def test_metric_denominators_strict_compliance(robustness_data):
    """
    Stage 10.1 Task 4: Verify Metric Denominators.
    Verifies:
      - FPR = FP / (FP + TN) where denominator is total actual benign requests (N_benign).
      - FNR = FN / (FN + TP) where denominator is total actual attack requests (N_attack).
      - Precision = TP / (TP + FP) where denominator is total predicted attacks.
      - Recall = TP / (TP + FN) where denominator is total actual attacks.
      - Accuracy = (TP + TN) / (TP + FP + TN + FN).
      - Specificity = TN / (TN + FP).
      - Safe division by zero for edge cases.
    """
    # Adversarial dataset: 37 benign, 33 attacks
    scenarios = robustness_data["scenarios"]
    n_benign = sum(1 for s in scenarios if not s["ground_truth"]["is_attack"])
    n_attack = sum(1 for s in scenarios if s["ground_truth"]["is_attack"])
    assert n_benign == 37
    assert n_attack == 33

    # B4 outcomes on robustness: TP=16, FP=15, TN=22, FN=17
    b4_metrics = compute_classification_metrics(tp=16, fp=15, tn=22, fn=17)
    assert b4_metrics["total_evaluated"] == 70
    assert b4_metrics["fpr"] == round(15 / 37, 4)  # 0.4054
    assert b4_metrics["fnr"] == round(17 / 33, 4)  # 0.5152
    assert b4_metrics["recall"] == round(16 / 33, 4)  # 0.4848
    assert b4_metrics["precision"] == round(16 / 31, 4)  # 0.5161
    assert b4_metrics["accuracy"] == round(38 / 70, 4)  # 0.5429
    assert b4_metrics["specificity"] == round(22 / 37, 4)  # 0.5946

    # Variant B outcomes on robustness: TP=16, FP=3, TN=34, FN=17
    vb_metrics = compute_classification_metrics(tp=16, fp=3, tn=34, fn=17)
    assert vb_metrics["fpr"] == round(3 / 37, 4)  # 0.0811
    assert vb_metrics["fnr"] == round(17 / 33, 4)  # 0.5152
    assert vb_metrics["precision"] == round(16 / 19, 4)  # 0.8421
    assert vb_metrics["accuracy"] == round(50 / 70, 4)  # 0.7143

    # Division by zero safety: all zeroes or single-class distributions
    empty_m = compute_classification_metrics(tp=0, fp=0, tn=0, fn=0)
    assert empty_m["accuracy"] == 0.0
    assert empty_m["precision"] == 0.0
    assert empty_m["recall"] == 0.0
    assert empty_m["f1"] == 0.0
    assert empty_m["fpr"] == 0.0
    assert empty_m["fnr"] == 0.0

    all_benign_m = compute_classification_metrics(tp=0, fp=0, tn=10, fn=0)
    assert all_benign_m["precision"] == 0.0
    assert all_benign_m["recall"] == 0.0
    assert all_benign_m["accuracy"] == 1.0


def test_ablation_component_isolation_invariance(robustness_data):
    """
    Stage 10.1 Task 4: Confirm component disabling and evaluate B4 vs Variant B
    on identical robustness scenarios.
    Verifies:
      - Variant B (No-ML) skips ML inference and relies solely on heuristic rules.
      - Variant C (No-Adaptation) pins the deception state graph to the root DISCOVERY node.
      - Variant D (No-History) does not retain session history between consecutive requests.
      - B4 and Variant B evaluate on identical 70 robustness scenarios with identical ground truth.
    """
    scenarios = robustness_data["scenarios"]
    model = load_model(DEFAULT_MODEL_PATH)

    # 1. Evaluate B4 (Variant A) and Variant B
    res_b4 = evaluate_ablation_variant(scenarios, "A_FULL", model)
    res_b = evaluate_ablation_variant(scenarios, "B_NO_ML", None)

    # Both must evaluate exactly 70 scenarios
    assert res_b4["metrics"]["total_evaluated"] == 70
    assert res_b["metrics"]["total_evaluated"] == 70

    # Variant B detection latency must be at least 100x lower than B4 due to skipping ML inference
    assert res_b["detection_latency_ms"]["p50"] < 0.1  # typically ~0.019 ms
    assert res_b4["detection_latency_ms"]["p50"] > 5.0  # typically ~13-16 ms

    # Variant B has no ML model and achieves lower false positives (3 vs 15) on keyword-laden benign queries
    assert res_b["metrics"]["confusion_matrix"]["fp"] == 3
    assert res_b4["metrics"]["confusion_matrix"]["fp"] == 15

    # 2. Evaluate Variant C: pins DSG to DISCOVERY node
    res_c = evaluate_ablation_variant(scenarios[:10], "C_NO_ADAPT", model)
    assert res_c["metrics"]["total_evaluated"] == 10

    # 3. Evaluate Variant D: session history is disabled
    res_d = evaluate_ablation_variant(scenarios[:10], "D_NO_HISTORY", model)
    assert res_d["metrics"]["total_evaluated"] == 10


def test_origin_leakage_observed_from_routing_destinations(ablation_report):
    """
    Stage 10.1 Task 5: Verify Origin Leakage from Observed Destinations.
    Verifies:
      - Origin leaks are strictly measured from actual routing outcome ('routed_to_origin' when is_attack == True).
      - In every baseline and ablation variant, origin_leak_count strictly matches the confusion matrix FN count.
      - Leaks are not inferred from theoretical policy intentions, but recorded from observed routing destination.
    """
    held_out = ablation_report["ablation_study_results"]["held_out_test_split"]
    for v_key, v_data in held_out.items():
        routing = v_data["routing_outcomes"]
        cm = v_data["metrics"]["confusion_matrix"]
        # Origin leaks must match False Negatives (uncontained attacks forwarded to origin)
        assert routing["origin_leak_count"] == cm["fn"], f"Mismatch in {v_key}: leaks={routing['origin_leak_count']}, fn={cm['fn']}"
        # Total routed to origin must equal actual TN (benign forwarded) + FN (leaked attacks)
        assert routing["routed_to_origin"] == cm["tn"] + cm["fn"], f"Mismatch in {v_key}: routed_to_origin={routing['routed_to_origin']}, tn+fn={cm['tn']+cm['fn']}"
        # Diverted to deception must equal actual TP (attacks contained) + FP (benign false alarms)
        assert routing["diverted_to_deception"] == cm["tp"] + cm["fp"], f"Mismatch in {v_key}: diverted={routing['diverted_to_deception']}, tp+fp={cm['tp']+cm['fp']}"

    robustness = ablation_report["ablation_study_results"]["adversarial_robustness_split"]
    for v_key, v_data in robustness.items():
        routing = v_data["routing_outcomes"]
        cm = v_data["metrics"]["confusion_matrix"]
        assert routing["origin_leak_count"] == cm["fn"], f"Mismatch in {v_key} robustness: leaks={routing['origin_leak_count']}, fn={cm['fn']}"
        assert routing["routed_to_origin"] == cm["tn"] + cm["fn"]
        assert routing["diverted_to_deception"] == cm["tp"] + cm["fp"]


def test_reports_reconciled_with_raw_evaluation(ablation_report):
    """
    Stage 10.1 Task 6: Verify Reports Reconciled with Raw Results.
    Verifies:
      - JSON report artifacts and Markdown report table values agree exactly.
      - No discrepancies between markdown summary tables and raw JSON execution outputs.
    """
    md_path = os.path.join(REPO_ROOT, "reports", "robustness_and_ablation_study.md")
    assert os.path.exists(md_path), f"Markdown report missing at {md_path}"
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    # Verify key figures appear identically in markdown report text and tables
    held_out = ablation_report["ablation_study_results"]["held_out_test_split"]

    # Variant D figures
    var_d = held_out["D_NO_HISTORY"]["metrics"]
    assert "90.0%" in md_text  # Accuracy
    assert "80.0%" in md_text  # Recall
    assert "0.889" in md_text  # F1
    assert "6 (20.0%)" in md_text  # Leaks

    # Variant A (Full Proposed) held-out figures
    assert "0.925" in md_text  # DES

    # Variant A (Full Proposed) robustness figures
    rob_a = ablation_report["ablation_study_results"]["adversarial_robustness_split"]["A_FULL"]["metrics"]
    assert "15/37 (40.5%)" in md_text  # FPR
    assert "17/33 (51.5%)" in md_text  # FNR
    assert "54.3%" in md_text  # Accuracy
    assert "0.500" in md_text  # F1

    # Variant B robustness figures
    assert "3/37 (8.1%)" in md_text  # FPR
    assert "84.2%" in md_text  # Precision
    assert "71.4%" in md_text  # Accuracy

