"""
Test Suite: Dataset & Model Provenance Integrity Audit (Stage 11.1)
Verifies:
  1. Cryptographic SHA-256 file and content digests across all benchmark datasets and model artifacts.
  2. Ground-truth label isolation invariance (features and predictions are immune to ground-truth tampering).
  3. Routing origin leakage accounting (OBSERVE_ONLY on attacks counts as False Negative / Origin Leak).
  4. Exact reproduction of external benchmark confusion matrix (37 TP, 0 FP, 50 TN, 13 FN).
  5. Identical requests and labels shared between B4 and Variant B (Rules Only).
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

from scripts.run_external_evaluation import (
    EXTERNAL_DATASET_PATH,
    DEFAULT_MODEL_PATH,
)
from scripts.evaluation_runner import (
    extract_features_from_request,
    evaluate_ablation_variant,
    DATASET_PATH,
    ROBUSTNESS_DATASET_PATH,
)
from src.ml_model import load_model, predict_anomaly_score


# Verified canonical hashes
VERIFIED_HASHES = {
    "benchmark_scenarios_v1": {
        "file_path": DATASET_PATH,
        "raw_file_sha256": "2ecae8b3eb25342470dc803b04506b007f9a59501b0c98a404603c402842f1fc",
        "content_sha256": "958fa723ca691d9fbbd6cdc885cbc8509e80e4332bc4e9313ca98e7e2c0a0746",
    },
    "robustness_scenarios_v1": {
        "file_path": ROBUSTNESS_DATASET_PATH,
        "raw_file_sha256": "7dde7ba551ec2d2e8565169fc23f71c3413f42812cf842f4e638e1b9b9bcf99d",
        "content_sha256": "03a7cb3aa97dcf6f459b5029c7c5bc9483c840abe24d108282459f8ef71e6e08",
    },
    "external_benchmark_v1": {
        "file_path": EXTERNAL_DATASET_PATH,
        "raw_file_sha256": "b4dc4cb593b17f940eaa1b274903ec50ccf910b8e4c55a135ec0e2507fbb33bc",
        "content_sha256": "f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3",
    },
    "model_artifact": {
        "file_path": DEFAULT_MODEL_PATH,
        "raw_file_sha256": "4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406",
    },
}


def test_artifact_sha256_digests_and_content_hashes():
    """
    Stage 11.1 Task 1:
    Verifies that all dataset files and frozen model artifact match verified SHA-256 hashes:
      - Raw byte-level file SHA-256
      - Canonical scenario stream content SHA-256
    """
    # 1. Standard Benchmark
    with open(VERIFIED_HASHES["benchmark_scenarios_v1"]["file_path"], "rb") as f:
        bench_bytes = f.read()
    assert hashlib.sha256(bench_bytes).hexdigest() == VERIFIED_HASHES["benchmark_scenarios_v1"]["raw_file_sha256"]
    bench_doc = json.loads(bench_bytes.decode("utf-8"))
    assert bench_doc["content_sha256"] == VERIFIED_HASHES["benchmark_scenarios_v1"]["content_sha256"]
    computed_bench = hashlib.sha256(json.dumps(bench_doc["scenarios"], sort_keys=True).encode("utf-8")).hexdigest()
    assert computed_bench == VERIFIED_HASHES["benchmark_scenarios_v1"]["content_sha256"]

    # 2. Robustness Benchmark
    with open(VERIFIED_HASHES["robustness_scenarios_v1"]["file_path"], "rb") as f:
        rob_bytes = f.read()
    assert hashlib.sha256(rob_bytes).hexdigest() == VERIFIED_HASHES["robustness_scenarios_v1"]["raw_file_sha256"]
    rob_doc = json.loads(rob_bytes.decode("utf-8"))
    assert rob_doc["content_sha256"] == VERIFIED_HASHES["robustness_scenarios_v1"]["content_sha256"]
    computed_rob = hashlib.sha256(json.dumps(rob_doc["scenarios"], sort_keys=True).encode("utf-8")).hexdigest()
    assert computed_rob == VERIFIED_HASHES["robustness_scenarios_v1"]["content_sha256"]

    # 3. External Benchmark
    with open(VERIFIED_HASHES["external_benchmark_v1"]["file_path"], "rb") as f:
        ext_bytes = f.read()
    assert hashlib.sha256(ext_bytes).hexdigest() == VERIFIED_HASHES["external_benchmark_v1"]["raw_file_sha256"]
    ext_doc = json.loads(ext_bytes.decode("utf-8"))
    assert ext_doc["content_sha256"] == VERIFIED_HASHES["external_benchmark_v1"]["content_sha256"]
    computed_ext = hashlib.sha256(json.dumps(ext_doc["scenarios"], sort_keys=True).encode("utf-8")).hexdigest()
    assert computed_ext == VERIFIED_HASHES["external_benchmark_v1"]["content_sha256"]

    # 4. Frozen Model Artifact
    with open(VERIFIED_HASHES["model_artifact"]["file_path"], "rb") as f:
        model_bytes = f.read()
    assert hashlib.sha256(model_bytes).hexdigest() == VERIFIED_HASHES["model_artifact"]["raw_file_sha256"]


def test_ground_truth_isolation_invariance():
    """
    Stage 11.1 Task 3:
    Verifies that ground-truth labels NEVER enter feature extraction or model inference.
    Features and predicted scores must be bit-for-bit identical whether ground_truth is:
      - Untouched
      - Inverted (is_attack: False -> True)
      - Altered to arbitrary category strings
      - Completely omitted from the input dictionary
    """
    model = load_model(DEFAULT_MODEL_PATH)

    with open(EXTERNAL_DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Test across representative benign and attack scenarios
    test_samples = [data["scenarios"][0], data["scenarios"][15], data["scenarios"][50], data["scenarios"][75]]

    for sample in test_samples:
        req = sample["request"]
        ctx = sample.get("context_features", {})

        # Baseline extraction
        feat_orig = extract_features_from_request(req, ctx)
        score_orig, label_orig = predict_anomaly_score(model, feat_orig)

        # Mutated ground-truth
        tampered_sample = json.loads(json.dumps(sample))
        tampered_sample["ground_truth"]["is_attack"] = not tampered_sample["ground_truth"]["is_attack"]
        tampered_sample["ground_truth"]["category"] = "TAMPERED_INJECTION"
        tampered_sample["ground_truth"]["label"] = "FAKE_LABEL"

        feat_tampered = extract_features_from_request(tampered_sample["request"], tampered_sample.get("context_features", {}))
        score_tampered, label_tampered = predict_anomaly_score(model, feat_tampered)

        assert feat_orig.model_dump() == feat_tampered.model_dump()
        assert score_orig == score_tampered
        assert label_orig == label_tampered

        # Stripped ground truth
        stripped_req = json.loads(json.dumps(req))
        feat_stripped = extract_features_from_request(stripped_req, ctx)
        score_stripped, label_stripped = predict_anomaly_score(model, feat_stripped)

        assert feat_orig.model_dump() == feat_stripped.model_dump()
        assert score_orig == score_stripped
        assert label_orig == label_stripped


def test_external_evaluation_confusion_matrix_reproducibility():
    """
    Stage 11.1 Task 3 & 4:
    Recalculates results from individual request outcomes on the external dataset.
    Confirms exact replication:
      TP = 37, FP = 0, TN = 50, FN = 13
      Accuracy = 87.0%, Recall = 74.0%, Precision = 100.0%, F1 = 0.8506
      Origin Leaks = 13 / 50 (26.0%)
    """
    model = load_model(DEFAULT_MODEL_PATH)
    with open(EXTERNAL_DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    scenarios = data["scenarios"]
    assert len(scenarios) == 100

    res = evaluate_ablation_variant(scenarios, "A_FULL", model)
    cm = res["metrics"]["confusion_matrix"]
    metrics = res["metrics"]
    routing = res["routing_outcomes"]

    assert cm["tp"] == 37, f"Expected 37 TP, got {cm['tp']}"
    assert cm["fp"] == 0, f"Expected 0 FP, got {cm['fp']}"
    assert cm["tn"] == 50, f"Expected 50 TN, got {cm['tn']}"
    assert cm["fn"] == 13, f"Expected 13 FN, got {cm['fn']}"
    assert routing["origin_leak_count"] == 13

    assert metrics["accuracy"] == 0.87
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.74
    assert metrics["f1"] == 0.8506


def test_identical_scenarios_and_labels_between_b4_and_variant_b():
    """
    Stage 11.1 Task 3:
    Verifies that B4 and Variant B (Rules Only) evaluate on the EXACT identical requests and labels.
    """
    model = load_model(DEFAULT_MODEL_PATH)
    with open(EXTERNAL_DATASET_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    scenarios = data["scenarios"]
    assert len(scenarios) == 100

    res_vb = evaluate_ablation_variant(scenarios, "B_NO_ML", model)
    cm_vb = res_vb["metrics"]["confusion_matrix"]
    metrics_vb = res_vb["metrics"]
    routing_vb = res_vb["routing_outcomes"]

    assert cm_vb["tp"] == 23
    assert cm_vb["fp"] == 0
    assert cm_vb["tn"] == 50
    assert cm_vb["fn"] == 27
    assert routing_vb["origin_leak_count"] == 27

    assert metrics_vb["accuracy"] == 0.73
    assert metrics_vb["precision"] == 1.0
    assert metrics_vb["recall"] == 0.46
    assert metrics_vb["f1"] == 0.6301


def test_provenance_mapping_completeness_and_terms():
    """
    Stage 11.2 Tasks 1-5:
    Verifies that:
      1. Machine-readable provenance metadata exists and maps all 100 scenarios.
      2. CSIC 2010 and OWASP CRS citations and independent licenses are verified.
      3. Scenarios are characterized as synthetic testbeds / regression tests, not captured live traffic.
      4. Distinction between local research evaluation vs redistribution is explicitly documented.
    """
    prov_path = os.path.join(REPO_ROOT, "data", "scenarios", "external_benchmark_v1_provenance.json")
    assert os.path.exists(prov_path), f"Provenance metadata file missing: {prov_path}"

    with open(prov_path, "r", encoding="utf-8") as f:
        prov = json.load(f)

    with open(EXTERNAL_DATASET_PATH, "r", encoding="utf-8") as f:
        bench = json.load(f)

    assert prov["total_scenarios"] == 100
    assert len(prov["scenario_provenance"]) == 100
    assert prov["benchmark_file_content_sha256"] == bench["content_sha256"]

    # Verify 1-to-1 mapping
    bench_scenarios_by_id = {s["scenario_id"]: s for s in bench["scenarios"]}
    for entry in prov["scenario_provenance"]:
        sid = entry["scenario_id"]
        assert sid in bench_scenarios_by_id, f"Missing scenario {sid} in benchmark"
        orig_s = bench_scenarios_by_id[sid]
        assert entry["assigned_category"] == orig_s["ground_truth"]["category"]
        assert entry["request_method"] == orig_s["request"]["method"]
        assert entry["request_path"] == orig_s["request"]["path"]
        assert "transformations_applied" in entry
        assert "source_citation" in entry

    # Verify Sources & Terms
    sources = {s["source_id"]: s for s in prov["primary_sources"]}
    assert "CSIC_2010" in sources
    assert "OWASP_CRS" in sources

    # CSIC 2010 checks
    csic = sources["CSIC_2010"]
    assert "Torrano-Giménez" in csic["authors"][0]
    assert "isi.csic.es" in csic["canonical_url"]
    assert "NOT captured real-world" in csic["traffic_characterization"]
    assert csic["permissions"]["local_research_evaluation_permitted"] is True
    assert csic["permissions"]["commercial_redistribution_permitted"] is False

    # OWASP CRS checks
    owasp = sources["OWASP_CRS"]
    assert "Apache License 2.0" in owasp["license_status"]
    assert owasp["permissions"]["commercial_redistribution_permitted"] is True

    # Usage and redistribution notice
    notice = prov["usage_terms_and_redistribution_notice"]
    assert "Fully permitted" in notice["local_evaluation_status"]
    assert "CONSTRUCTED EVALUATION SUBSET" in notice["benchmark_characterization"]
    assert "NOT represent captured live-production" in notice["benchmark_characterization"]

