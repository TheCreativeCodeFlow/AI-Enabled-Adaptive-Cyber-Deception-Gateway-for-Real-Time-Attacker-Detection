# External Benchmark Validation and Routing Semantics Evaluation (Stage 11)

**Document Reference:** `reports/external_benchmark_evaluation.md`  
**Execution Timestamp:** `2026-10-19T12:52:51.748189+00:00`  
**Git Commit Reference:** `39bab2cc90011d86d382ae2f4fc9b6ef9a1912a1`  
**Machine-Readable Report (JSON):** `reports/external_benchmark_results.json`  
**Dataset Reference:** `data/scenarios/external_benchmark_v1.json`  
**Dataset SHA-256:** `f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3`  
**Model Artifact SHA-256:** `4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406`  

---

## 1. Executive Summary & Assessment

This report presents an independent external evaluation of the **AI-Enabled Adaptive Cyber Deception Gateway** against a standardized public HTTP benchmark derived from the **CSIC 2010 HTTP Dataset** and the **OWASP ModSecurity Core Rule Set (CRS) Benchmark**.

### Key Evaluation Findings:
1. **Public Dataset Generalization:**
   - On the 100-scenario external HTTP dataset (50 Benign e-commerce / API requests, 50 Attacks across SQLi, Traversal, CMDi, XSS, Parameter Tampering, Recon), the proposed gateway (**B4 / Variant A**) achieved:
     - **Accuracy: 87.0%**
     - **Precision: 100.0%**
     - **Recall / Containment Rate: 74.0%**
     - **F1 Score: 0.851**
     - **False Positive Rate (FPR): 0.0% (0/50 benign falsely diverted)**
     - **False Negative Rate / Origin Leakage (FNR): 26.0% (13/50 attacks leaked to origin)**
2. **Comparison with Rules-Only Baseline (Variant B):**
   - **Variant B (Rules Only)** achieved:
     - **Accuracy: 73.0%**
     - **Precision: 100.0%**
     - **Recall: 46.0%**
     - **FPR: 0.0% (0/50)**
     - **FNR: 54.0% (27/50)**
     - **p50 Latency: 0.017 ms vs. 13.584 ms**
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
| **B1: Direct Passthrough** | Reverse Proxy (No Sec) | 0 | 0 | 50 | 50 | 0.0% | 0.0% | 0.000 | 50.0% | 50/50 (100.0%) | 0/50 (0.0%) | 0.2 µs | N/A (passthrough) |
| **B2: Static Heuristic** | Substring Matching | 3 | 0 | 50 | 47 | 100.0% | 6.0% | 0.113 | 53.0% | 47/50 (94.0%) | 0/50 (0.0%) | 0.4 µs | 0.3 µs |
| **B3: Rule-Based Adaptive**| Regex Heuristics | 23 | 0 | 50 | 27 | 100.0% | 46.0% | 0.630 | 73.0% | 27/50 (54.0%) | 0/50 (0.0%) | 0.004 ms | 0.004 ms |
| **B4: Proposed Gateway** | ML + Heuristics + DSG | **37** | **0** | **50** | **13** | **100.0%** | **74.0%** | **0.851** | **87.0%** | **13/50 (26.0%)** | **0/50 (0.0%)** | **13.584 ms** | **13.583 ms** |

### 3.2 Architectural Ablation Variants

| Configuration | Description | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | Leaks (FNR) | False Pos (FPR) | p50 Gateway Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A (Full Proposed - B4)** | Full ML + Rules + Controller | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.584 ms |
| **Variant B (No-ML Ablation)** | Rules Only (ML Disabled) | 23 | 0 | 50 | 27 | 100.0% | 46.0% | 0.630 | 73.0% | 27/50 (54.0%) | 0/50 (0.0%) | **0.017 ms** |
| **Variant C (No-Adaptation)** | Flat Mock (No Adaptive DSG) | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.531 ms |
| **Variant D (No-History)** | Stateless Request Evaluation | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.491 ms |

---

## 4. Per-Category Breakdown on External Dataset

| Attack Category | Total Samples | TP | FP | TN | FN | Precision | Recall | Accuracy | Origin Leaks |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN            ** | 50 | 0 | 0 | 50 | 0 | 0.0% | 0.0% | 100.0% | 0 (0.0%) |
| **CMDI              ** | 8 | 6 | 0 | 0 | 2 | 100.0% | 75.0% | 75.0% | 2 (25.0%) |
| **PARAM_TAMPERING   ** | 6 | 2 | 0 | 0 | 4 | 100.0% | 33.3% | 33.3% | 4 (66.7%) |
| **RECON             ** | 6 | 5 | 0 | 0 | 1 | 100.0% | 83.3% | 83.3% | 1 (16.7%) |
| **SQLI              ** | 12 | 11 | 0 | 0 | 1 | 100.0% | 91.7% | 91.7% | 1 (8.3%) |
| **TRAVERSAL         ** | 10 | 9 | 0 | 0 | 1 | 100.0% | 90.0% | 90.0% | 1 (10.0%) |
| **XSS               ** | 8 | 4 | 0 | 0 | 4 | 100.0% | 50.0% | 50.0% | 4 (50.0%) |

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
   - **Containment:** Adversary actively trapped inside honeypot without reaching origin ($L_{\text{leak}} = 0$).
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
