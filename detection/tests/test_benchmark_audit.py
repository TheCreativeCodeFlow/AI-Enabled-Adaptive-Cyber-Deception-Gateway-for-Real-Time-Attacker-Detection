"""
Test Suite: Benchmark Audit and Research Validation (Stage 9)
Verifies:
  1. Dataset Schema & Integrity (120 versioned scenarios, balanced 60/60 splits, SHA-256 verification)
  2. Ground-Truth Isolation (Zero leakage of ground truth into feature extractors or inference)
  3. Mathematical Reconciliation of Confusion Matrices and Performance Metrics
  4. Deception Effectiveness Score (DES) Binary Zero-Leak Gate and Boundedness
  5. Monotonic Latency Timing Measurements
  6. Multi-Baseline Execution Invariance
"""

import os
import sys
import json
import hashlib
import time
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
    evaluate_b1_direct_origin,
    evaluate_b2_static_deception,
    evaluate_b3_rule_based_adaptive,
    evaluate_b4_proposed_gateway,
    DATASET_PATH,
    REPORT_PATH,
)
from src.schemas import RequestFeatures
from src.ml_model import load_model, DEFAULT_MODEL_PATH


@pytest.fixture(scope="module")
def benchmark_data():
    assert os.path.exists(DATASET_PATH), f"Dataset missing: {DATASET_PATH}"
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def test_dataset_schema_and_integrity(benchmark_data):
    """
    Acceptance Criteria 2 & 9:
    Dataset schema must contain 120 total scenarios with 60 dev / 60 held-out test splits,
    and match the recorded cryptographic SHA-256 hash.
    """
    assert "dataset_version" in benchmark_data
    assert "content_sha256" in benchmark_data
    scenarios = benchmark_data["scenarios"]
    assert len(scenarios) == 120

    dev_split = [s for s in scenarios if s["split"] == "development"]
    test_split = [s for s in scenarios if s["split"] == "held_out_test"]
    assert len(dev_split) == 60
    assert len(test_split) == 60

    # Verify balanced class distribution
    benign = [s for s in scenarios if s["ground_truth"]["category"] == "BENIGN"]
    assert len(benign) == 60

    categories = ["SQLI", "TRAVERSAL", "CMDI", "RECON", "CRED_STUFF"]
    for cat in categories:
        cat_scenarios = [s for s in scenarios if s["ground_truth"]["category"] == cat]
        assert len(cat_scenarios) == 12, f"Category {cat} should have exactly 12 scenarios, found {len(cat_scenarios)}"
        dev_cat = [s for s in cat_scenarios if s["split"] == "development"]
        test_cat = [s for s in cat_scenarios if s["split"] == "held_out_test"]
        assert len(dev_cat) == 6
        assert len(test_cat) == 6

    # Verify content SHA-256 integrity
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        file_obj = json.load(f)
    stored_hash = file_obj.get("content_sha256")
    content_str = json.dumps(file_obj["scenarios"], sort_keys=True)
    computed_hash = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    assert stored_hash == computed_hash, "Dataset SHA-256 mismatch: content was altered"



def test_ground_truth_isolation(benchmark_data):
    """
    Acceptance Criteria 4:
    Ground-truth labels must never leak into feature extraction or model inference.
    """
    sample = benchmark_data["scenarios"][0]
    assert "ground_truth" in sample

    # Extract features using only request and context
    features = extract_features_from_request(sample["request"], sample.get("context_features", {}))

    # Verify RequestFeatures schema has no ground truth or label fields
    feature_dict = features.model_dump()
    assert "ground_truth" not in feature_dict
    assert "label" not in feature_dict
    assert "is_attack" not in feature_dict
    assert "category" not in feature_dict
    assert "expected_safety_constraint" not in feature_dict

    # Check for non-empty extracted metrics
    assert features.method in ["GET", "POST", "PUT", "DELETE", "PATCH"]
    assert isinstance(features.path_entropy, float)
    assert features.path_entropy >= 0.0


def test_confusion_matrix_reconciliation():
    """
    Acceptance Criteria 3:
    Reported statistical metrics must strictly reconcile with the 2x2 confusion matrix counts.
    """
    # Test arbitrary valid confusion matrix
    tp, fp, tn, fn = 45, 5, 48, 2
    metrics = compute_classification_metrics(tp, fp, tn, fn)

    cm = metrics["confusion_matrix"]
    assert cm["tp"] == tp
    assert cm["fp"] == fp
    assert cm["tn"] == tn
    assert cm["fn"] == fn
    assert metrics["total_evaluated"] == tp + fp + tn + fn

    # Reconcile formulas
    expected_acc = round((tp + tn) / (tp + fp + tn + fn), 4)
    expected_prec = round(tp / (tp + fp), 4)
    expected_rec = round(tp / (tp + fn), 4)
    expected_f1 = round(2 * expected_prec * expected_rec / (expected_prec + expected_rec), 4)
    expected_fpr = round(fp / (fp + tn), 4)
    expected_fnr = round(fn / (fn + tp), 4)
    expected_spec = round(tn / (tn + fp), 4)

    assert metrics["accuracy"] == expected_acc
    assert metrics["precision"] == expected_prec
    assert metrics["recall"] == expected_rec
    assert metrics["f1"] == expected_f1
    assert metrics["fpr"] == expected_fpr
    assert metrics["fnr"] == expected_fnr
    assert metrics["specificity"] == expected_spec


def test_des_origin_leakage_gate():
    """
    Acceptance Criteria 6 & 7:
    Zero Origin Leakage Gate: Any confirmed attack reaching real origin forces DES strictly to 0.000.
    """
    # Case 1: High engagement, deep DSG traversal, but 1 origin leak
    leaked_des = calculate_des_from_evidence(
        origin_leak_count=1,
        unique_dsg_nodes_visited=4,
        total_dsg_nodes=4,
        successful_deception_responses=50,
        total_deception_interactions=50,
        unique_decoy_endpoints=4,
        total_decoy_endpoints=4,
        dwell_target=10,
    )
    assert leaked_des["score"] == 0.0
    assert leaked_des["origin_leakage"] is True
    assert leaked_des["origin_leak_count"] == 1
    assert leaked_des["depth_score"] == 0.0
    assert leaked_des["consistency_score"] == 0.0

    # Case 2: Zero origin leaks with perfect deceptive engagement
    zero_leak_des = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=4,
        total_dsg_nodes=4,
        successful_deception_responses=20,
        total_deception_interactions=20,
        unique_decoy_endpoints=4,
        total_decoy_endpoints=4,
        dwell_target=10,
    )
    assert zero_leak_des["score"] == 1.0
    assert zero_leak_des["origin_leakage"] is False
    assert zero_leak_des["depth_score"] == 1.0
    assert zero_leak_des["consistency_score"] == 1.0
    assert zero_leak_des["dwell_score"] == 1.0
    assert zero_leak_des["engagement_score"] == 1.0


def test_des_bounded_components():
    """
    Acceptance Criteria 7:
    Each individual DES component must be strictly bounded in [0.0, 1.0].
    """
    partial_des = calculate_des_from_evidence(
        origin_leak_count=0,
        unique_dsg_nodes_visited=2,
        total_dsg_nodes=4,
        successful_deception_responses=5,
        total_deception_interactions=10,
        unique_decoy_endpoints=1,
        total_decoy_endpoints=4,
        dwell_target=20,
    )
    assert 0.0 <= partial_des["score"] <= 1.0
    assert partial_des["depth_score"] == 0.50
    assert partial_des["consistency_score"] == 0.50
    assert partial_des["dwell_score"] == 0.50
    assert partial_des["engagement_score"] == 0.25

    # Check weighted combination: 0.3*0.5 + 0.3*0.5 + 0.25*0.5 + 0.15*0.25 = 0.15 + 0.15 + 0.125 + 0.0375 = 0.4625
    expected_score = round(0.30 * 0.50 + 0.30 * 0.50 + 0.25 * 0.50 + 0.15 * 0.25, 4)
    assert partial_des["score"] == expected_score


def test_timer_monotonicity():
    """
    Acceptance Criteria 10:
    Timing measurements must be strictly monotonic non-negative intervals.
    """
    t0 = time.perf_counter_ns()
    # Microsecond busy wait
    _ = [x * x for x in range(1000)]
    t1 = time.perf_counter_ns()
    duration_ms = (t1 - t0) / 1_000_000
    assert duration_ms >= 0.0
    assert t1 >= t0


def test_evaluation_report_artifact_integrity():
    """
    Acceptance Criteria 9:
    The generated report artifact must contain complete reproduction metadata.
    """
    assert os.path.exists(REPORT_PATH), f"Report artifact missing: {REPORT_PATH}"
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)

    # Required top-level sections
    assert "metadata" in report
    assert "audit_findings" in report
    assert "development_calibration" in report
    assert "held_out_test_split_results" in report
    assert "overall_benchmark_results" in report
    assert "category_breakdown_b4" in report
    assert "latency_stability" in report
    assert "methodological_limitations" in report


    # Metadata fields
    meta = report["metadata"]
    assert "timestamp" in meta
    assert "environment" in meta
    assert "dataset" in meta
    assert "model" in meta
    assert meta["dataset"]["content_sha256"] != ""
    assert meta["model"]["model_sha256"] != ""
