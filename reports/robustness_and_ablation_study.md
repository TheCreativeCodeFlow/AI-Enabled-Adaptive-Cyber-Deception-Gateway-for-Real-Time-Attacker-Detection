# Adversarial Robustness and Architectural Ablation Study (Stage 10)

**Document Reference:** `reports/robustness_and_ablation_study.md`  
**Execution Timestamp:** `2026-10-19T09:53:40.330204+00:00`  
**Git Commit Reference:** `b63ba15`  
**Machine-Readable Report (JSON):** `reports/ablation_and_robustness_results.json`  
**Target Architecture:** AI-Enabled Adaptive Cyber Deception Gateway  

---

## 1. Executive Summary

This study presents a rigorous empirical audit, architectural ablation, and adversarial robustness evaluation of the proposed **AI-Enabled Adaptive Cyber Deception Gateway (Variant A / Baseline B4)**.

Stage 9 reported perfect performance (100.0% Precision, 100.0% Recall, 1.000 F1, 0 origin leaks) on a held-out test split of 60 synthetic HTTP requests. In this study, we audited the actual source code, raw results, and generated reports to investigate whether those results represent genuine adversarial generalization or synthetic calibration artifacts.

### Key Empirical Audit Findings:
1. **Did the 100% Generalization Claim Survive? NO.**  
   When evaluated against a held-out adversarial robustness dataset of 70 realistic probes (containing benign sensitive keywords, encoded evasions, and unseen attack vectors), B4's accuracy collapsed from **100.0% to 54.3%** (F1 = 0.500).
2. **False Diversion Vulnerability (FPR = 40.5%):**  
   15 out of 37 benign requests containing security terminology (e.g., `/api/search?q=how+to+use+sql+union+in+queries`, `/assets/admin-dashboard-preview.png`) were falsely diverted into deception because naive bag-of-words keyword counting lacks semantic context.
3. **Evasion & Zero-Day Origin Leakage (FNR = 51.5%):**  
   17 out of 33 attack variants (including double-encoded path traversals `%252e%252e%252f`, newline command injection `%0Aid`, Server-Side Template Injection `{{7*7}}`, NoSQL injections, and LDAP/Log4j patterns) completely bypassed both rule heuristics and ML anomaly scoring, leaking directly to the production origin.
4. **Architectural Ablation Insights:**
   - **No-ML (Variant B):** Disabling ML reduced latency by **99.9%** (from 13.593 ms to 0.015 ms), with a modest recall drop on standard attacks (100% to 83.3%). On the adversarial dataset, Variant B actually outperformed B4 in accuracy (**71.4% vs 54.3%**) and had far fewer false positives (3 vs 15) because it was immune to benign keyword false positives.
   - **No-Adaptation (Variant C):** Disabling adaptive Deception State Graph (DSG) transitions degraded the Deception Effectiveness Score (DES) from **0.925 to 0.662** (a 39.7% drop in active containment quality).
   - **No-Behavioral-History (Variant D):** Disabling session stickiness caused multi-probe attacker sequences to leak to origin (6 leaks), reducing test recall to **80.0%** (with **90.0% accuracy** and **F1 = 0.889**) and collapsing DES to **0.000**.
5. **DES Mathematical Reconciliation:**  
   Held-out test DES is **0.925** because 3 of 4 DSG states were visited ($D_{\text{depth}} = 3/4 = 0.750$), while the full benchmark reached all 4 states ($D_{\text{depth}} = 1.000$), yielding **1.000**. On the adversarial dataset, origin leakage tripped the binary gate, forcing DES to **0.000**.

---

## 2. Experimental Datasets & Cryptographic Integrity

All evaluation runs use fixed, cryptographically hashed JSON datasets strictly separated into distinct partitions.

```
+-------------------------------------------------------------------------------+
|                       DATASET REPOSITORY & ISOLATION                           |
+-------------------------------------------------------------------------------+
| 1. Standardized Benchmark v1.0.0 (data/scenarios/benchmark_scenarios_v1.json) |
|    - Content SHA-256: 958fa723ca691d9fbbd6cdc885cbc8509e80e4332bc4e9313ca98e7e2c0a0746   |
|    - Total: 120 scenarios                                                     |
|    - Development Split: 60 (30 Benign, 30 Attacks) -> Calibration Only       |
|    - Held-Out Test Split: 60 (30 Benign, 30 Attacks) -> Never Seen in Train   |
+-------------------------------------------------------------------------------+
| 2. Adversarial Robustness v1.0.0 (data/scenarios/robustness_scenarios_v1.json) |
|    - Content SHA-256: 03a7cb3aa97dcf6f459b5029c7c5bc9483c840abe24d108282459f8ef71e6e08   |
|    - Total: 70 scenarios (37 Benign, 33 Attacks)                              |
|    - Zero Model Retraining: Model parameters were frozen prior to evaluation. |
+-------------------------------------------------------------------------------+
| 3. Model Artifact (detection/model.joblib)                                     |
|    - Model SHA-256: 4d76bac3bdd82425f8d760aa8437f0eece55c02b82b41614844251292d4fb406   |
|    - Pipeline: StandardScaler + RandomForestClassifier (n_estimators=100)     |
+-------------------------------------------------------------------------------+
```

### Strict Ground-Truth Isolation
Ground-truth objects (`ground_truth: {label, is_attack, category}`) are completely stripped prior to feature extraction. In automated safety regression tests, `RequestFeatures` schemas were validated to contain zero label leakage.

---

## 3. Multi-Variant Architectural Ablation Study

To isolate the individual contribution of each system component, we formulated four controlled variants and evaluated them under identical request streams:

- **Variant A (Proposed Gateway - B4):** Full system (Multi-Factor ML + Deterministic Controller + Adaptive DSG + Sticky Session Memory).
- **Variant B (No-ML Ablation):** Deterministic rules and policy only; ML model disabled (`blended_score = base_score`).
- **Variant C (No-Adaptation Ablation):** Full detection enabled, but deception is flat and static (pinned to `DISCOVERY` state, no DSG progression).
- **Variant D (No-Behavioral-History Ablation):** Full detection and adaptive DSG, but stateless routing (no session stickiness; zero accumulated behavioral history).
- **Baselines B1–B3:** Direct Passthrough (B1), Static Heuristic Deception (B2), and Rule-Based Adaptive Routing (B3).

### 3.1 Results on Held-Out Test Set (60 Scenarios: 30 Benign, 30 Standard Attacks)

| Configuration | TP | FP | TN | FN | Precision | Recall (TPR) | F1 Score | Accuracy | Origin Leaks | DES (0–1) | Gateway Latency (p50) | Detection Latency (p50) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B1: Direct Origin** | 0 | 0 | 30 | 30 | 0.0% | 0.0% | 0.000 | 50.0% | 30 (100.0%) | **0.000** | 0.2 µs | N/A (passthrough) |
| **B2: Static Heuristic** | 3 | 0 | 30 | 27 | 100.0% | 10.0% | 0.182 | 55.0% | 27 (90.0%) | **0.000** | 0.4 µs | 0.3 µs |
| **B3: Rule-Based Adaptive** | 16 | 0 | 30 | 14 | 100.0% | 53.3% | 0.696 | 76.7% | 14 (46.7%) | **0.000** | 0.002 ms | 0.002 ms |
| **Variant A: Full Proposed** | **30** | **0** | **30** | **0** | **100.0%** | **100.0%** | **1.000** | **100.0%** | **0 (0.0%)** | **0.925** | **13.593 ms** | **13.592 ms** |
| **Variant B: No-ML Ablation** | 25 | 0 | 30 | 5 | 100.0% | 83.3% | 0.909 | 91.7% | 5 (16.7%) | **0.000** | **0.015 ms** | **0.015 ms** |
| **Variant C: No-Adaptation** | 30 | 0 | 30 | 0 | 100.0% | 100.0% | 1.000 | 100.0% | 0 (0.0%) | **0.662** | 13.533 ms | 13.533 ms |
| **Variant D: No-History** | 24 | 0 | 30 | 6 | 100.0% | 80.0% | 0.889 | 90.0% | 6 (20.0%) | **0.000** | 13.614 ms | 13.613 ms |

### 3.2 Results on Adversarial Robustness Set (70 Scenarios: 37 Benign, 33 Attacks)

| Configuration | TP | FP | TN | FN | Precision | Recall (TPR) | F1 Score | Accuracy | False Positives (FPR) | Origin Leaks (FNR) | DES (0–1) | Gateway Latency (p50) | Detection Latency (p50) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A: Full Proposed** | 16 | 15 | 22 | 17 | 51.6% | 48.5% | 0.500 | 54.3% | 15/37 (40.5%) | 17/33 (51.5%) | **0.000** | 13.568 ms | 13.567 ms |
| **Variant B: No-ML Ablation** | 16 | 3 | 34 | 17 | **84.2%** | 48.5% | **0.615** | **71.4%** | **3/37 (8.1%)** | 17/33 (51.5%) | **0.000** | **0.017 ms** | **0.016 ms** |
| **Variant C: No-Adaptation** | 16 | 15 | 22 | 17 | 51.6% | 48.5% | 0.500 | 54.3% | 15/37 (40.5%) | 17/33 (51.5%) | **0.000** | 13.613 ms | 13.613 ms |
| **Variant D: No-History** | 16 | 14 | 23 | 17 | 53.3% | 48.5% | 0.508 | 55.7% | 14/37 (37.8%) | 17/33 (51.5%) | **0.000** | 13.590 ms | 13.589 ms |

---

## 4. Reconciliation of Variant D (Stateless Decisions)

A critical question investigated during this audit was resolving the apparent discrepancy between:
- Table reported **Accuracy = 90.0%** and **F1 = 0.889**.
- Narrative statement that "disabling session stickiness reduces recall to **80.0%** and causes **six origin leaks**."

### Complete Reconciliation & Confusion Matrix Audit:
- **Evaluation Dataset:** `data/scenarios/benchmark_scenarios_v1.json` (Held-Out Test Split).
- **Evaluation Scope:** $N = 60$ total scenarios (30 Benign requests, 30 Ground-Truth Attack requests).
- **Observed $2 \times 2$ Confusion Matrix:**
  $$\begin{matrix} & \text{Pred Benign} & \text{Pred Attack} \\ \text{Actual Benign} & TN = 30 & FP = 0 \\ \text{Actual Attack} & FN = 6 & TP = 24 \end{matrix}$$
- **Exact Statistical Derivations:**
  - $\text{Accuracy} = \frac{TP + TN}{TP + FP + TN + FN} = \frac{24 + 30}{60} = \frac{54}{60} = \mathbf{90.0\%}$ (Denominator: $N = 60$ total evaluated requests)
  - $\text{Recall (TPR)} = \frac{TP}{TP + FN} = \frac{24}{24 + 6} = \frac{24}{30} = \mathbf{80.0\%}$ (Denominator: $N_{\text{attack}} = 30$ ground-truth attacks)
  - $\text{Precision} = \frac{TP}{TP + FP} = \frac{24}{24 + 0} = \frac{24}{24} = \mathbf{100.0\%}$ (Denominator: $N_{\text{diverted}} = 24$ requests diverted to deception)
  - $\text{F1 Score} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \times 1.0 \times 0.8}{1.0 + 0.8} = \frac{1.6}{1.8} = \mathbf{0.8889}$
  - $\text{Origin Leaks} = FN = 6$ out of 30 attacks = $\mathbf{20.0\%}$ (tripping the Zero-Leak gate, $\text{DES} = \mathbf{0.000}$)

> **Scientific Resolution:** Both the 90.0% accuracy and 80.0% recall refer to the **exact same evaluation run and scope** ($N=60$). The 10 percentage point divergence between accuracy (90%) and recall (80%) is mathematically inevitable: all 30 benign requests were correctly forwarded to origin ($TN=30, FP=0$), which boosts overall accuracy to 90%, whereas attack containment specifically failed on 6 multi-probe requests ($FN=6$), pulling attack recall down to 80%.

---

## 5. Deception Effectiveness Score (DES) Mathematical Reconciliation

The Deception Effectiveness Score (DES) evaluates the containment capability of the dynamic deception runtime using an evidence-based formulation:

$$\text{DES} = \mathbb{I}[L_{\text{leak}} = 0] \cdot \left( 0.30 \cdot D_{\text{depth}} + 0.30 \cdot C_{\text{consistency}} + 0.25 \cdot T_{\text{dwell}} + 0.15 \cdot E_{\text{engagement}} \right)$$

### 5.1 Reconciliation of Reported Values:

1. **Held-Out Test Set (DES = 0.925):**
   - Origin Leaks: $L_{\text{leak}} = 0 \implies \mathbb{I}[L=0] = 1.0$.
   - DSG Node Depth: 3 of 4 states visited (`DISCOVERY`, `EXPLOITATION`, `CREDENTIAL_ACCESS`). `RECONNAISSANCE` was not explored by test attack paths.  
     $D_{\text{depth}} = 3/4 = 0.750 \implies 0.30 \times 0.750 = \mathbf{0.225}$.
   - State Consistency: 30 of 30 synthetic responses generated.  
     $C_{\text{consistency}} = 1.000 \implies 0.30 \times 1.000 = \mathbf{0.300}$.
   - Attacker Dwell: 30 interactions against target of 10.  
     $T_{\text{dwell}} = 1.000 \implies 0.25 \times 1.000 = \mathbf{0.250}$.
   - Decoy Engagement: 20 decoy interactions touched.  
     $E_{\text{engagement}} = 1.000 \implies 0.15 \times 1.000 = \mathbf{0.150}$.
   - **Total:** $0.225 + 0.300 + 0.250 + 0.150 = \mathbf{0.925}$.

2. **Combined Benchmark Set (DES = 1.000):**
   - All 4 DSG states were explored (`RECONNAISSANCE` included in dev split) $\implies D_{\text{depth}} = 4/4 = 1.000 \implies 0.30 \times 1.000 = \mathbf{0.300}$.
   - **Total:** $0.300 + 0.300 + 0.250 + 0.150 = \mathbf{1.000}$.

3. **Adversarial Robustness Set (DES = 0.000):**
   - 17 evasive attacks reached the origin ($L_{\text{leak}} = 17$).
   - The binary gate enforced $\mathbb{I}[L=0] = 0.0$, collapsing the total score to **0.000**.

4. **Missing Observations Rule:**  
   When total deception interactions are zero (e.g. B1 direct origin forwarding), all components evaluate strictly to 0.0 and are never silently treated as perfect scores.

---

## 6. Adversarial Robustness Breakdown (70 Probe Scenarios)

### 6.1 B4 Breakdown by Probe Category

| Probe Category | Total Samples | TP | FP | TN | FN | Precision | Recall | Accuracy | Origin Leaks |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN                  ** | 15 | 0 | 2 | 13 | 0 | 0.0% | 100.0% | 86.7% | 0 (0.0%) |
| **BENIGN_SUSPICIOUS_TOKENS** | 16 | 0 | 13 | 3 | 0 | 0.0% | 100.0% | 18.8% | 0 (0.0%) |
| **CMDI                    ** | 4 | 3 | 0 | 0 | 1 | 100.0% | 75.0% | 75.0% | 1 (25.0%) |
| **CMDI_HEADER             ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **CRED_STUFF              ** | 2 | 0 | 0 | 0 | 2 | 100.0% | 0.0% | 0.0% | 2 (100.0%) |
| **GRAPHQL_PROBE           ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **LDAP_INJECTION          ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **LOG4J_JNDI              ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **MALFORMED               ** | 6 | 0 | 0 | 6 | 0 | 100.0% | 100.0% | 100.0% | 0 (0.0%) |
| **MALFORMED_ATTACK        ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **NOSQLI                  ** | 2 | 0 | 0 | 0 | 2 | 100.0% | 0.0% | 0.0% | 2 (100.0%) |
| **RECON                   ** | 4 | 4 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0 (0.0%) |
| **SQLI                    ** | 5 | 5 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0 (0.0%) |
| **SQLI_HEADER             ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **SSTI                    ** | 2 | 0 | 0 | 0 | 2 | 100.0% | 0.0% | 0.0% | 2 (100.0%) |
| **TRAVERSAL               ** | 5 | 4 | 0 | 0 | 1 | 100.0% | 80.0% | 80.0% | 1 (20.0%) |
| **WEBDAV_PROBE            ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **XSS                     ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |
| **XXE                     ** | 1 | 0 | 0 | 0 | 1 | 100.0% | 0.0% | 0.0% | 1 (100.0%) |

### 6.2 Root Causes of False Diversions & Origin Leaks
- **Benign Token False Positives (FPR = 40.5%):** Denominator is actual benign requests ($N_{\text{benign}} = 37$). Naive substring keyword matching without AST context flags search queries (`q=how+to+use+sql+union+in+queries`) and documentation URLs.
- **Evasion Origin Leaks (FNR = 51.5%):** Denominator is actual attack requests ($N_{\text{attack}} = 33$). Double URI encoding (`%252e%252e%252f`), newline delimiters (`%0Aid`), and novel syntax (SSTI, NoSQL, XXE) bypass the model.

---

## 7. Latency Analysis: Gateway vs. Detection Decomposition

| Variant | Architecture | p50 Gateway Latency | p95 Gateway Latency | p50 Detection Latency |
| :--- | :--- | :---: | :---: | :---: |
| **B1** | Direct Passthrough | 0.2 µs | 0.3 µs | N/A |
| **B2** | Static Substring Heuristic | 0.4 µs | 0.5 µs | 0.3 µs |
| **B3** | Regex Adaptive Routing | 0.002 ms | 0.007 ms | 0.002 ms |
| **Variant B** | Rules-Only Policy (No ML) | **0.015 ms** | 0.027 ms | **0.015 ms** |
| **Variant A** | Full Proposed Gateway (B4) | **13.593 ms** | 13.702 ms | **13.592 ms** |

### Multi-Run Stability (5 Random Seeds)
Across seeds `[42, 101, 202, 303, 404]`, p50 gateway latency was:
$$\text{Latency (p50)} = 13.584\text{ ms} \pm 0.022\text{ ms} \quad (\text{Min: } 13.559\text{ ms}, \text{ Max: } 13.610\text{ ms})$$

---

## 8. Threats to Scientific Validity & Roadmap

1. **Synthetic Data Limitations:** Synthetic training and benchmark grammars do not replicate human attacker intuition, multi-hop evasion, or bespoke zero-days.
2. **Production Roadmap:**
   - Implement context-aware AST parsing to eliminate benign keyword false positives.
   - Implement multi-pass recursive canonicalization to eliminate double-encoded traversals.
   - Implement hybrid two-tier routing: rules-only filter for clear benign/malicious traffic ($15\text{ µs}$), invoking ML only on borderline scores ($15\text{ ms}$).
