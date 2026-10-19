# External Benchmark Validation and Routing Semantics Evaluation (Stage 11)

**Document Reference:** `reports/external_benchmark_evaluation.md`  
**Execution Timestamp:** `2026-10-19T13:23:16.740978+00:00`  
**Git Commit Reference:** `161cb10ab8888e1200c30acba3c7077a1191e94e`  
**Machine-Readable Report (JSON):** `reports/external_benchmark_results.json`  
**Dataset Reference:** `data/scenarios/external_benchmark_v1.json`  
**Dataset Content SHA-256:** `f11d6894b9b5d486785008f2062d88d19263e2330971dae07bd96813741940c3`  
**Model Artifact SHA-256:** `4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406`  
**Provenance Metadata Reference:** `data/scenarios/external_benchmark_v1_provenance.json`  

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
     - **p50 Latency: 0.016 ms vs. 13.587 ms**
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
| **B4: Proposed Gateway** | ML + Heuristics + DSG | **37** | **0** | **50** | **13** | **100.0%** | **74.0%** | **0.851** | **87.0%** | **13/50 (26.0%)** | **0/50 (0.0%)** | **13.587 ms** | **13.586 ms** |

### 3.2 Architectural Ablation Variants

| Configuration | Description | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | Leaks (FNR) | False Pos (FPR) | p50 Gateway Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A (Full Proposed - B4)** | Full ML + Rules + Controller | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.587 ms |
| **Variant B (No-ML Ablation)** | Rules Only (ML Disabled) | 23 | 0 | 50 | 27 | 100.0% | 46.0% | 0.630 | 73.0% | 27/50 (54.0%) | 0/50 (0.0%) | **0.016 ms** |
| **Variant C (No-Adaptation)** | Flat Mock (No Adaptive DSG) | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.592 ms |
| **Variant D (No-History)** | Stateless Request Evaluation | 37 | 0 | 50 | 13 | 100.0% | 74.0% | 0.851 | 87.0% | 13/50 (26.0%) | 0/50 (0.0%) | 13.596 ms |

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

## 6. Dataset Provenance, Source Taxonomy & Licensing Integrity (Stage 11.3 Audit)

1. **Source Taxonomy & Attribution Breakdown:**
   - **CSIC 2010 (69 scenarios: 35 Benign, 34 Attacks):** Authentic HTTP requests targeting the experimental `tienda1` e-commerce application, generated via automated web spiders and vulnerability scanners (Paros proxy, Nessus).
   - **OWASP Core Rule Set (16 scenarios: 0 Benign, 16 Attacks):** Attack payloads derived from OWASP CRS regression test cases (rules 913100, 930100, 932100, 941100, 942100) adapted into modern REST parameters and JSON schemas.
   - **Project-Created Benign Baseline Controls (15 scenarios: 15 Benign, 0 Attacks):** Scenarios EXT-BEN-035 through EXT-BEN-049 were authored directly by the project in Stage 11 to benchmark modern REST API paths (`/api/v1/products`, `/api/v1/health`, etc.) alongside 2010 JSP routes. *Attribution Correction:* Previously misattributed in metadata to 'OWASP Web Controls', they are now explicitly classified as project-created controls. (EXT-BEN-050 is verified as authentic CSIC 2010 traffic).

2. **Verified Licensing Terms & Legal Analysis:**
   - **CSIC 2010:** Original publisher website (`isi.csic.es` / `tic.itefi.csic.es`) published the dataset for research into web intrusion detection without a formal open-source license grant. Third-party catalogue descriptions (e.g. UNB ISCX or Kaggle 'Public/Academic' tags) represent repository categorizations rather than an explicit legal grant from CSIC. Local research evaluation is standard academic research fair use, but commercial redistribution rights remain **unresolved and legally ambiguous**. It is recommended to obtain written authorization from CSIC or replace with an open-licensed dataset prior to commercial redistribution.
   - **OWASP CRS:** Licensed under Apache License 2.0 (release `v3.3.x / v4.0.0`). Redistribution requires preserving copyright notices, license texts, and stating modifications prominently. **Scope Limitation:** The Apache 2.0 license applies **strictly to the 16 CRS-derived attack payloads** and does **not** extend to CSIC 2010 records or project-created material.

3. **Traffic Characterization & Generalization Scope:**
   - ALL 100 scenarios represent a **constructed evaluation subset** using automated testbeds (CSIC 2010), security regression tests (OWASP CRS), and synthetic controls (Project).
   - **NONE of the scenarios represent captured live-production network traffic from human attackers.**
   - The benchmark provides un-tuned cross-dataset validation, confirming detection robustness across distinct injection syntaxes, but does not claim universal generalization in live production environments.

---

## 7. Reproducibility & Commands

To independently reproduce the external benchmark results:
```bash
# 1. Generate / verify external dataset
python3 scripts/generate_external_dataset.py

# 2. Run external benchmark evaluation
python3 scripts/run_external_evaluation.py
```
