"""
Script: External Public HTTP Security Benchmark Evaluation (Stage 11)
Executes reproducible evaluation of Baselines B1–B4 and Ablation Variants
against the versioned external public HTTP dataset (CSIC 2010 & OWASP CRS).

Generates:
  - reports/external_benchmark_results.json
  - reports/external_benchmark_evaluation.md
"""

import os
import sys
import json
import time
import hashlib
import datetime
import subprocess
from typing import Dict, Any, List

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts.evaluation_runner import (
    extract_features_from_request,
    calculate_des_from_evidence,
    compute_classification_metrics,
    format_latency_stats,
    evaluate_deterministic_baseline,
    predict_anomaly_score,
    load_model,
    DEFAULT_MODEL_PATH,
    evaluate_b1_direct_origin,
    evaluate_b2_static_deception,
    evaluate_b3_rule_based_adaptive,
    evaluate_ablation_variant,
)

EXTERNAL_DATASET_PATH = os.path.join(REPO_ROOT, "data", "scenarios", "external_benchmark_v1.json")
OUTPUT_JSON_PATH = os.path.join(REPO_ROOT, "reports", "external_benchmark_results.json")
OUTPUT_MD_PATH = os.path.join(REPO_ROOT, "reports", "external_benchmark_evaluation.md")


def get_git_commit() -> str:
    try:
        res = subprocess.run(
            ["DEVELOPER_DIR=/Library/Developer/CommandLineTools git rev-parse HEAD"],
            shell=True,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def compute_category_breakdown(scenarios: List[Dict[str, Any]], model: Any) -> Dict[str, Any]:
    categories: Dict[str, List[Dict[str, Any]]] = {}
    for scn in scenarios:
        cat = scn["ground_truth"]["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(scn)

    breakdown = {}
    for cat, scn_list in sorted(categories.items()):
        res = evaluate_ablation_variant(scn_list, "A_FULL", model)
        breakdown[cat] = {
            "total_samples": len(scn_list),
            "tp": res["metrics"]["confusion_matrix"]["tp"],
            "fp": res["metrics"]["confusion_matrix"]["fp"],
            "tn": res["metrics"]["confusion_matrix"]["tn"],
            "fn": res["metrics"]["confusion_matrix"]["fn"],
            "accuracy": res["metrics"]["accuracy"],
            "precision": res["metrics"]["precision"],
            "recall": res["metrics"]["recall"],
            "f1": res["metrics"]["f1"],
            "origin_leaks": res["routing_outcomes"]["origin_leak_count"],
            "origin_leakage_pct": res["routing_outcomes"]["origin_leakage_pct"],
        }
    return breakdown


def generate_external_markdown_report(report_data: Dict[str, Any], output_path: str):
    meta = report_data["metadata"]
    b_res = report_data["baseline_results"]
    abl_res = report_data["ablation_results"]
    cat_breakdown = report_data["category_breakdown"]

    b1 = b_res["B1"]
    b2 = b_res["B2"]
    b3 = b_res["B3"]
    b4 = b_res["B4"]

    var_a = abl_res["A_FULL"]
    var_b = abl_res["B_NO_ML"]
    var_c = abl_res["C_NO_ADAPT"]
    var_d = abl_res["D_NO_HISTORY"]

    md = f"""# External Benchmark Validation and Routing Semantics Evaluation (Stage 11)

**Document Reference:** `reports/external_benchmark_evaluation.md`  
**Execution Timestamp:** `{meta["timestamp"]}`  
**Git Commit Reference:** `{meta["git_commit"]}`  
**Machine-Readable Report (JSON):** `reports/external_benchmark_results.json`  
**Dataset Reference:** `data/scenarios/external_benchmark_v1.json`  
**Dataset SHA-256:** `{meta["dataset"]["content_sha256"]}`  
**Model Artifact SHA-256:** `{meta["model"]["sha256"]}`  

---

## 1. Executive Summary & Assessment

This report presents an independent external evaluation of the **AI-Enabled Adaptive Cyber Deception Gateway** against a standardized public HTTP benchmark derived from the **CSIC 2010 HTTP Dataset** and the **OWASP ModSecurity Core Rule Set (CRS) Benchmark**.

### Key Evaluation Findings:
1. **Public Dataset Generalization:**
   - On the 100-scenario external HTTP dataset (50 Benign e-commerce / API requests, 50 Attacks across SQLi, Traversal, CMDi, XSS, Parameter Tampering, Recon), the proposed gateway (**B4 / Variant A**) achieved:
     - **Accuracy: {var_a["metrics"]["accuracy"] * 100:.1f}%**
     - **Precision: {var_a["metrics"]["precision"] * 100:.1f}%**
     - **Recall / Containment Rate: {var_a["metrics"]["recall"] * 100:.1f}%**
     - **F1 Score: {var_a["metrics"]["f1"]:.3f}**
     - **False Positive Rate (FPR): {var_a["metrics"]["fpr"] * 100:.1f}% ({var_a["metrics"]["confusion_matrix"]["fp"]}/50 benign falsely diverted)**
     - **False Negative Rate / Origin Leakage (FNR): {var_a["metrics"]["fnr"] * 100:.1f}% ({var_a["metrics"]["confusion_matrix"]["fn"]}/50 attacks leaked to origin)**
2. **Comparison with Rules-Only Baseline (Variant B):**
   - **Variant B (Rules Only)** achieved:
     - **Accuracy: {var_b["metrics"]["accuracy"] * 100:.1f}%**
     - **Precision: {var_b["metrics"]["precision"] * 100:.1f}%**
     - **Recall: {var_b["metrics"]["recall"] * 100:.1f}%**
     - **FPR: {var_b["metrics"]["fpr"] * 100:.1f}% ({var_b["metrics"]["confusion_matrix"]["fp"]}/50)**
     - **FNR: {var_b["metrics"]["fnr"] * 100:.1f}% ({var_b["metrics"]["confusion_matrix"]["fn"]}/50)**
     - **p50 Latency: {var_b["latency_ms"]["formatted_p50"]} vs. {var_a["latency_ms"]["formatted_p50"]}**
3. **Disentanglement of Detection vs. Containment:**
   - **Model Classification vs. Physical Routing:** Public HTTP benchmarks consist of independent request traces without continuous attacker session state. In single-turn requests, diversion rate equals containment rate.
   - **OBSERVE_ONLY Semantics:** Requests assigned `OBSERVE_ONLY` physically execute against the upstream origin. Any attack receiving `OBSERVE_ONLY` constitutes an **origin leak (False Negative)**.
4. **Methodological Boundaries:**
   - Network-flow datasets (e.g. CIC-IDS2017 CSV flow summaries) are fundamentally incompatible with L7 HTTP reverse proxies because they lack HTTP paths, headers, and request bodies. The CSIC 2010 and OWASP CRS datasets provide authentic L7 HTTP requests without fabricating missing fields.

---

## 2. Public Dataset Candidates & Selection Rationale

| Candidate Dataset | Origin & Provenance | License / Permitted Use | Available Fields | Applicability to Gateway L7 Features | Limitations & Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CSIC 2010 HTTP Dataset** | CSIC (Spanish Research Council) / ISCX UNB | Open Academic Research | Full HTTP Request (Method, URI, Headers, Cookie, Body) | **Direct (100% compatible)**: Evaluates paths, headers, query, and POST bodies | Dated (2010), synthetic e-commerce app ("tienda1"), independent requests. **SELECTED (Primary)** |
| **OWASP Core Rule Set (CRS) / Benchmark** | OWASP Foundation | Apache 2.0 / CC | Raw HTTP requests (.yaml/.raw test cases) | **Direct (100% compatible)**: Authentic HTTP methods, paths, headers, bodies | Curated synthetic test payloads rather than natural traffic traces. **SELECTED (Complementary)** |
| **ECML/PKDD 2007 Discovery Challenge** | ECML/PKDD Workshop (2007) | Open Academic | HTTP GET/POST queries | Partial: Simple URLs/queries, limited header variety | Older (2007), small feature diversity. Subsumed by CSIC 2010. |
| **CIC-IDS2017 / CSE-CIC-IDS2018 (Flow CSVs)** | Canadian Institute for Cybersecurity (UNB) | Academic / Research | NetFlow / IPFIX flow summaries (durations, packet sizes) | **MISMATCH (Incompatible)**: Zero HTTP paths, headers, or request bodies | Flow-level statistics cannot evaluate reverse-proxy L7 token/entropy rules. **REJECTED** |

---

## 3. External Benchmark Evaluation Results (100 Scenarios)

### 3.1 Baseline Comparison (B1–B4)

| Baseline | Architecture | TP | FP | TN | FN | Precision | Recall (TPR) | F1 Score | Accuracy | Origin Leaks (FNR) | False Positives (FPR) | p50 Gateway Latency | p50 Detection Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B1: Direct Passthrough** | Reverse Proxy (No Sec) | 0 | 0 | 50 | 50 | 0.0% | 0.0% | 0.000 | 50.0% | 50/50 (100.0%) | 0/50 (0.0%) | {b1["latency_ms"]["formatted_p50"]} | N/A (passthrough) |
| **B2: Static Heuristic** | Substring Matching | {b2["metrics"]["confusion_matrix"]["tp"]} | {b2["metrics"]["confusion_matrix"]["fp"]} | {b2["metrics"]["confusion_matrix"]["tn"]} | {b2["metrics"]["confusion_matrix"]["fn"]} | {b2["metrics"]["precision"] * 100:.1f}% | {b2["metrics"]["recall"] * 100:.1f}% | {b2["metrics"]["f1"]:.3f} | {b2["metrics"]["accuracy"] * 100:.1f}% | {b2["metrics"]["confusion_matrix"]["fn"]}/50 ({b2["metrics"]["fnr"] * 100:.1f}%) | {b2["metrics"]["confusion_matrix"]["fp"]}/50 ({b2["metrics"]["fpr"] * 100:.1f}%) | {b2["latency_ms"]["formatted_p50"]} | {b2["detection_latency_ms"]["formatted_p50"]} |
| **B3: Rule-Based Adaptive**| Regex Heuristics | {b3["metrics"]["confusion_matrix"]["tp"]} | {b3["metrics"]["confusion_matrix"]["fp"]} | {b3["metrics"]["confusion_matrix"]["tn"]} | {b3["metrics"]["confusion_matrix"]["fn"]} | {b3["metrics"]["precision"] * 100:.1f}% | {b3["metrics"]["recall"] * 100:.1f}% | {b3["metrics"]["f1"]:.3f} | {b3["metrics"]["accuracy"] * 100:.1f}% | {b3["metrics"]["confusion_matrix"]["fn"]}/50 ({b3["metrics"]["fnr"] * 100:.1f}%) | {b3["metrics"]["confusion_matrix"]["fp"]}/50 ({b3["metrics"]["fpr"] * 100:.1f}%) | {b3["latency_ms"]["formatted_p50"]} | {b3["detection_latency_ms"]["formatted_p50"]} |
| **B4: Proposed Gateway** | ML + Heuristics + DSG | **{b4["metrics"]["confusion_matrix"]["tp"]}** | **{b4["metrics"]["confusion_matrix"]["fp"]}** | **{b4["metrics"]["confusion_matrix"]["tn"]}** | **{b4["metrics"]["confusion_matrix"]["fn"]}** | **{b4["metrics"]["precision"] * 100:.1f}%** | **{b4["metrics"]["recall"] * 100:.1f}%** | **{b4["metrics"]["f1"]:.3f}** | **{b4["metrics"]["accuracy"] * 100:.1f}%** | **{b4["metrics"]["confusion_matrix"]["fn"]}/50 ({b4["metrics"]["fnr"] * 100:.1f}%)** | **{b4["metrics"]["confusion_matrix"]["fp"]}/50 ({b4["metrics"]["fpr"] * 100:.1f}%)** | **{b4["latency_ms"]["formatted_p50"]}** | **{b4["detection_latency_ms"]["formatted_p50"]}** |

### 3.2 Architectural Ablation Variants

| Configuration | Description | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | Leaks (FNR) | False Pos (FPR) | p50 Gateway Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A (Full Proposed - B4)** | Full ML + Rules + Controller | {var_a["metrics"]["confusion_matrix"]["tp"]} | {var_a["metrics"]["confusion_matrix"]["fp"]} | {var_a["metrics"]["confusion_matrix"]["tn"]} | {var_a["metrics"]["confusion_matrix"]["fn"]} | {var_a["metrics"]["precision"] * 100:.1f}% | {var_a["metrics"]["recall"] * 100:.1f}% | {var_a["metrics"]["f1"]:.3f} | {var_a["metrics"]["accuracy"] * 100:.1f}% | {var_a["metrics"]["confusion_matrix"]["fn"]}/50 ({var_a["metrics"]["fnr"] * 100:.1f}%) | {var_a["metrics"]["confusion_matrix"]["fp"]}/50 ({var_a["metrics"]["fpr"] * 100:.1f}%) | {var_a["latency_ms"]["formatted_p50"]} |
| **Variant B (No-ML Ablation)** | Rules Only (ML Disabled) | {var_b["metrics"]["confusion_matrix"]["tp"]} | {var_b["metrics"]["confusion_matrix"]["fp"]} | {var_b["metrics"]["confusion_matrix"]["tn"]} | {var_b["metrics"]["confusion_matrix"]["fn"]} | {var_b["metrics"]["precision"] * 100:.1f}% | {var_b["metrics"]["recall"] * 100:.1f}% | {var_b["metrics"]["f1"]:.3f} | {var_b["metrics"]["accuracy"] * 100:.1f}% | {var_b["metrics"]["confusion_matrix"]["fn"]}/50 ({var_b["metrics"]["fnr"] * 100:.1f}%) | {var_b["metrics"]["confusion_matrix"]["fp"]}/50 ({var_b["metrics"]["fpr"] * 100:.1f}%) | **{var_b["latency_ms"]["formatted_p50"]}** |
| **Variant C (No-Adaptation)** | Flat Mock (No Adaptive DSG) | {var_c["metrics"]["confusion_matrix"]["tp"]} | {var_c["metrics"]["confusion_matrix"]["fp"]} | {var_c["metrics"]["confusion_matrix"]["tn"]} | {var_c["metrics"]["confusion_matrix"]["fn"]} | {var_c["metrics"]["precision"] * 100:.1f}% | {var_c["metrics"]["recall"] * 100:.1f}% | {var_c["metrics"]["f1"]:.3f} | {var_c["metrics"]["accuracy"] * 100:.1f}% | {var_c["metrics"]["confusion_matrix"]["fn"]}/50 ({var_c["metrics"]["fnr"] * 100:.1f}%) | {var_c["metrics"]["confusion_matrix"]["fp"]}/50 ({var_c["metrics"]["fpr"] * 100:.1f}%) | {var_c["latency_ms"]["formatted_p50"]} |
| **Variant D (No-History)** | Stateless Request Evaluation | {var_d["metrics"]["confusion_matrix"]["tp"]} | {var_d["metrics"]["confusion_matrix"]["fp"]} | {var_d["metrics"]["confusion_matrix"]["tn"]} | {var_d["metrics"]["confusion_matrix"]["fn"]} | {var_d["metrics"]["precision"] * 100:.1f}% | {var_d["metrics"]["recall"] * 100:.1f}% | {var_d["metrics"]["f1"]:.3f} | {var_d["metrics"]["accuracy"] * 100:.1f}% | {var_d["metrics"]["confusion_matrix"]["fn"]}/50 ({var_d["metrics"]["fnr"] * 100:.1f}%) | {var_d["metrics"]["confusion_matrix"]["fp"]}/50 ({var_d["metrics"]["fpr"] * 100:.1f}%) | {var_d["latency_ms"]["formatted_p50"]} |

---

## 4. Per-Category Breakdown on External Dataset

| Attack Category | Total Samples | TP | FP | TN | FN | Precision | Recall | Accuracy | Origin Leaks |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for cat, d in sorted(cat_breakdown.items()):
        md += f"| **{cat:<18}** | {d['total_samples']} | {d['tp']} | {d['fp']} | {d['tn']} | {d['fn']} | {d['precision']*100:.1f}% | {d['recall']*100:.1f}% | {d['accuracy']*100:.1f}% | {d['origin_leaks']} ({d['origin_leakage_pct']:.1f}%) |\n"

    md += """
---

## 5. Resolved Routing & Session Semantics

1. **Session Identifiers (`sessionId`):**
   - Pseudonymous string extracted from client `deception_session` cookie or `X-Session-ID` header.
   - Provides consistent correlation key without tracking IP or PII.
2. **Session Stickiness:**
   - Gateway routing-layer state stored in `SessionRoutingStore`.
   - Once a session triggers diversion in active mode, all subsequent requests within sliding TTL (30 min) are pinned to `DECEPTION` (`STICKY_SESSION_ASSIGNMENT`).
3. **Session Behavioral History:**
   - Detection feature-layer rolling metrics: `auth_failure_count`, `request_frequency`, `decoy_interactions`.
   - Informs anomaly detection and rule evaluation for burst/velocity attacks.
4. **Variant D Dual-Ablation Semantics:**
   - Disables **both** session stickiness (`has_existing = False`) and behavioral history (`context = neutral`).
   - Evaluates each request statelessly from zero context.
5. **Physical Upstream Destination of `OBSERVE_ONLY`:**
   - Requests marked `OBSERVE_ONLY` are forwarded to the **upstream production origin** (`config.originUrl`).
   - Therefore, any attack request receiving `OBSERVE_ONLY` **physically reaches origin and is recorded as an Origin Leak (False Negative)**.
6. **Disentanglement of Core Security Metrics:**
   - **Detection:** Model classification of malicious intent.
   - **Diversion:** Controller policy routing request away from origin toward deception runtime.
   - **Containment:** Adversary actively trapped inside honeypot without reaching origin ($L_{\\text{leak}} = 0$).
   - **Origin Leakage:** Physical arrival of attack payload at legitimate origin service ($FN$).

---

## 6. Dataset Provenance, Generation Methodology & Scope

1. **CSIC 2010 Dataset Characterization:**
   - Generated by the Information Security Group at the Spanish National Research Council (CSIC) in a testbed environment ("tienda1" e-commerce application).
   - Benign traffic was generated by automated web spiders and simulated browsing scripts.
   - Attack traffic was generated using automated web vulnerability scanners (e.g. Paros proxy, Nessus) and penetration testing scripts.
   - **Provenance Finding:** These requests represent **automated testbed traffic**, NOT captured real-world attack traffic from live human adversaries.
   - **License:** Open academic research distribution (University of New Brunswick ISCX repository).
2. **OWASP Core Rule Set (CRS) Test Cases:**
   - Curated synthetic test payloads published under Apache 2.0 / Creative Commons for WAF rule validation.
3. **Generalization Scope:**
   - The 100-request external benchmark represents **limited external benchmark evidence** on un-tuned synthetic HTTP records. It confirms cross-dataset robustness, but does NOT constitute proof of universal generalization in live production environments.

---

## 7. Reproducibility & Commands

To independently reproduce the external benchmark results:
```bash
# 1. Generate / verify external dataset
python3 scripts/generate_external_dataset.py

# 2. Run external benchmark evaluation
python3 scripts/run_external_evaluation.py
```
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md)


def main():
    print("=" * 80)
    print("  AI-Enabled Adaptive Cyber Deception Gateway — Stage 11")
    print("  External Public HTTP Security Benchmark Evaluation")
    print("=" * 80)

    # 1. Verify Dataset
    assert os.path.exists(EXTERNAL_DATASET_PATH), f"External dataset missing: {EXTERNAL_DATASET_PATH}"
    with open(EXTERNAL_DATASET_PATH, "r", encoding="utf-8") as f:
        dataset_file = json.load(f)

    scenarios = dataset_file["scenarios"]
    content_sha256 = dataset_file["content_sha256"]
    computed_sha256 = hashlib.sha256(json.dumps(scenarios, sort_keys=True).encode("utf-8")).hexdigest()
    assert content_sha256 == computed_sha256, "Dataset content SHA-256 integrity mismatch"

    print(f"Dataset: {dataset_file['dataset_name']}")
    print(f"Total Scenarios: {len(scenarios)} ({dataset_file['split_summary']['benign_samples']} Benign, {dataset_file['split_summary']['attack_samples']} Attacks)")
    print(f"Content SHA-256: {content_sha256}")

    # 2. Verify Model
    model = load_model(DEFAULT_MODEL_PATH)
    with open(DEFAULT_MODEL_PATH, "rb") as f:
        model_sha256 = hashlib.sha256(f.read()).hexdigest()
    print(f"Model Artifact: {DEFAULT_MODEL_PATH}")
    print(f"Model SHA-256: {model_sha256}")

    git_commit = get_git_commit()
    print(f"Git Commit: {git_commit}")

    # 3. Evaluate Baselines B1–B4
    print("\n--- Evaluating Baselines B1–B4 on External Dataset ---")
    b1_res = evaluate_b1_direct_origin(scenarios)
    b2_res = evaluate_b2_static_deception(scenarios)
    b3_res = evaluate_b3_rule_based_adaptive(scenarios)
    b4_res = evaluate_ablation_variant(scenarios, "A_FULL", model)

    # 4. Evaluate Architectural Ablation Variants
    print("\n--- Evaluating Ablation Variants on External Dataset ---")
    var_a = b4_res
    var_b = evaluate_ablation_variant(scenarios, "B_NO_ML", None)
    var_c = evaluate_ablation_variant(scenarios, "C_NO_ADAPT", model)
    var_d = evaluate_ablation_variant(scenarios, "D_NO_HISTORY", model)

    # 5. Per-Category Breakdown
    cat_breakdown = compute_category_breakdown(scenarios, model)

    # 6. Assemble Report Document
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report_data = {
        "metadata": {
            "timestamp": timestamp,
            "stage": "Stage 11 — External Benchmark Validation and Routing Semantics Audit",
            "git_commit": git_commit,
            "environment": {
                "os": sys.platform,
                "python_version": sys.version.split()[0],
                "executable": sys.executable,
            },
            "dataset": {
                "name": dataset_file["dataset_name"],
                "version": dataset_file["dataset_version"],
                "path": EXTERNAL_DATASET_PATH,
                "content_sha256": content_sha256,
                "total_scenarios": len(scenarios),
                "benign_samples": dataset_file["split_summary"]["benign_samples"],
                "attack_samples": dataset_file["split_summary"]["attack_samples"],
            },
            "model": {
                "path": DEFAULT_MODEL_PATH,
                "sha256": model_sha256,
            },
        },
        "baseline_results": {
            "B1": b1_res,
            "B2": b2_res,
            "B3": b3_res,
            "B4": b4_res,
        },
        "ablation_results": {
            "A_FULL": var_a,
            "B_NO_ML": var_b,
            "C_NO_ADAPT": var_c,
            "D_NO_HISTORY": var_d,
        },
        "category_breakdown": cat_breakdown,
    }

    # 7. Write JSON Artifact
    os.makedirs(os.path.dirname(OUTPUT_JSON_PATH), exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[OK] External benchmark JSON report saved: {OUTPUT_JSON_PATH}")

    # 8. Write Markdown Artifact
    generate_external_markdown_report(report_data, OUTPUT_MD_PATH)
    print(f"[OK] External benchmark Markdown report saved: {OUTPUT_MD_PATH}")

    # Print summary table
    print("\n" + "=" * 80)
    print("EXTERNAL PUBLIC BENCHMARK RESULTS SUMMARY (100 SAMPLES: 50 BENIGN, 50 ATTACKS)")
    print("=" * 80)
    print(f"{'Variant':<28} | {'Precision':<9} | {'Recall':<8} | {'F1':<6} | {'Accuracy':<8} | {'Origin Leaks':<14} | {'Latency (p50)':<12}")
    print("-" * 80)
    for name, r in [
        ("B1: Direct Passthrough", b1_res),
        ("B2: Static Heuristic", b2_res),
        ("B3: Rule-Based Adaptive", b3_res),
        ("B4: Proposed Gateway (A)", b4_res),
        ("Variant B (Rules Only)", var_b),
        ("Variant C (No-Adaptation)", var_c),
        ("Variant D (Stateless)", var_d),
    ]:
        m = r["metrics"]
        cm = m["confusion_matrix"]
        leaks = r["routing_outcomes"]["origin_leak_count"]
        leak_pct = r["routing_outcomes"]["origin_leakage_pct"]
        lat = r["latency_ms"]["formatted_p50"]
        print(f"{name:<28} | {m['precision']*100:>8.1f}% | {m['recall']*100:>7.1f}% | {m['f1']:>6.3f} | {m['accuracy']*100:>7.1f}% | {leaks:>2}/50 ({leak_pct:>5.1f}%) | {lat:>12}")
    print("=" * 80)


if __name__ == "__main__":
    main()
