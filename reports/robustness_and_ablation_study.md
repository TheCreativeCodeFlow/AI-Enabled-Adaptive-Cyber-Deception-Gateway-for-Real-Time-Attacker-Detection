# Adversarial Robustness and Architectural Ablation Study (Stage 10)

**Document Reference:** `reports/robustness_and_ablation_study.md`  
**Execution Timestamp:** 2026-10-19T08:54:40+00:00  
**Machine-Readable Report:** `reports/ablation_and_robustness_results.json`  
**Target Architecture:** AI-Enabled Adaptive Cyber Deception Gateway  

---

## 1. Executive Summary

This study presents a rigorous empirical audit, architectural ablation, and adversarial robustness evaluation of the proposed **AI-Enabled Adaptive Cyber Deception Gateway (Variant A / B4)**.

Stage 9 reported perfect performance (100.0% Precision, 100.0% Recall, 1.000 F1, 0 origin leaks) on a held-out test split of 60 synthetic HTTP requests. In this study, we investigated whether those results represent true adversarial generalization or synthetic calibration artifacts.

### Key Empirical Findings:
1. **Did the 100% Generalization Claim Survive? NO.**  
   When evaluated against a held-out adversarial robustness dataset of 70 realistic probes (containing benign sensitive keywords, encoded evasions, and unseen attack vectors), B4's accuracy collapsed from **100.0% to 54.3%** ($\text{F1} = 0.500$).
2. **False Diversion Vulnerability (40.5% FPR):**  
   15 out of 37 benign requests containing security terminology (e.g., `/api/search?q=how+to+use+sql+union+in+queries`, `/assets/admin-dashboard-preview.png`) were falsely diverted into deception because naive bag-of-words keyword counting lacks semantic context.
3. **Evasion & Zero-Day Origin Leakage (51.5% FNR):**  
   17 out of 33 attack variants (including double-encoded path traversals `%252e%252e%252f`, newline command injection `%0Aid`, Server-Side Template Injection `{{7*7}}`, NoSQL injections, and LDAP/Log4j patterns) completely bypassed both rule heuristics and ML anomaly scoring, leaking directly to the production origin.
4. **Architectural Ablation Insights:**
   - **No-ML (Variant B):** Disabling ML reduced latency by **99.9%** (from $15.91\text{ ms}$ to $0.015\text{ ms}$), with a modest recall drop on standard attacks (100% to 83.3%). On the adversarial dataset, Variant B actually outperformed B4 in accuracy (**71.4% vs 54.3%**) because it was immune to benign keyword false positives.
   - **No-Adaptation (Variant C):** Disabling adaptive Deception State Graph (DSG) transitions degraded the Deception Effectiveness Score (DES) from **0.925 to 0.662** (a 39.7% drop in active containment quality).
   - **No-Behavioral-History (Variant D):** Disabling session stickiness caused multi-probe attacker sequences to leak to origin, reducing test recall to 80.0% and collapsing DES to **0.000**.
5. **DES Mathematical Reconciliation:**  
   Held-out test DES is **0.925** because only 3 of 4 DSG states were visited ($D_{\text{depth}} = 3/4 = 0.750$), while the full benchmark reached all 4 states ($D_{\text{depth}} = 1.000$), yielding **1.000**. On the adversarial dataset, origin leakage tripped the binary gate, forcing DES to **0.000**.

---

## 2. Experimental Datasets & Cryptographic Integrity

All evaluation runs use fixed, cryptographically hashed JSON datasets strictly separated into distinct partitions.

```
+-------------------------------------------------------------------------------+
|                       DATASET REPOSITORY & ISOLATION                           |
+-------------------------------------------------------------------------------+
| 1. Standardized Benchmark v1.0.0 (data/scenarios/benchmark_scenarios_v1.json) |
|    - Content SHA-256: 958fa723ca691d9fbbd6cdc885cbc8509e80e4332bc4e9313ca...   |
|    - Total: 120 scenarios                                                     |
|    - Development Split: 60 (30 Benign, 30 Attacks) -> Calibration Only       |
|    - Held-Out Test Split: 60 (30 Benign, 30 Attacks) -> Never Seen in Train   |
+-------------------------------------------------------------------------------+
| 2. Adversarial Robustness v1.0.0 (data/scenarios/robustness_scenarios_v1.json) |
|    - Content SHA-256: 03a7cb3aa97dcf6f459b5029c7c5bc9483c840abe24d1082824...   |
|    - Total: 70 scenarios (37 Benign, 33 Attacks)                              |
|    - Zero Model Retraining: Model parameters were frozen prior to evaluation. |
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

| Configuration | Precision | Recall | F1 Score | Accuracy | Origin Leaks | DES (0–1) | Gateway Latency (p50) | Detection Latency (p50) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B1: Direct Origin** | 0.0% | 0.0% | 0.000 | 50.0% | 30 (100.0%) | **0.000** | 0.2 µs | N/A (passthrough) |
| **B2: Static Heuristic** | 100.0% | 10.0% | 0.182 | 55.0% | 27 (90.0%) | **0.000** | 0.4 µs | 0.3 µs |
| **B3: Rule-Based Adaptive** | 100.0% | 53.3% | 0.696 | 76.7% | 14 (46.7%) | **0.000** | 0.003 ms | 0.002 ms |
| **Variant A: Full Proposed** | **100.0%** | **100.0%** | **1.000** | **100.0%** | **0 (0.0%)** | **0.925** | **15.912 ms** | **15.911 ms** |
| **Variant B: No-ML Ablation** | 100.0% | 83.3% | 0.909 | 91.7% | 5 (16.7%) | **0.000** | **0.015 ms** | **0.015 ms** |
| **Variant C: No-Adaptation** | 100.0% | 100.0% | 1.000 | 100.0% | 0 (0.0%) | **0.662** | 12.855 ms | 12.854 ms |
| **Variant D: No-History** | 100.0% | 80.0% | 0.889 | 90.0% | 6 (20.0%) | **0.000** | 12.828 ms | 12.827 ms |

### 3.2 Results on Adversarial Robustness Set (70 Scenarios: 37 Benign, 33 Attacks)

| Configuration | Precision | Recall | F1 Score | Accuracy | False Positives | Origin Leaks | DES (0–1) | Gateway Latency (p50) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Variant A: Full Proposed** | 51.6% | 48.5% | 0.500 | 54.3% | 15 (40.5%) | 17 (51.5%) | **0.000** | 14.555 ms |
| **Variant B: No-ML Ablation** | **84.2%** | 48.5% | **0.615** | **71.4%** | **3 (8.1%)** | 17 (51.5%) | **0.000** | **0.019 ms** |
| **Variant C: No-Adaptation** | 51.6% | 48.5% | 0.500 | 54.3% | 15 (40.5%) | 17 (51.5%) | **0.000** | 16.100 ms |
| **Variant D: No-History** | 53.3% | 48.5% | 0.508 | 55.7% | 14 (37.8%) | 17 (51.5%) | **0.000** | 14.964 ms |

---

## 4. Adversarial Breakdown & Root-Cause Analysis

### 4.1 Detailed Performance by Probe Category (Variant A / B4)

| Probe Category | Total Samples | TP | FP | TN | FN | Category Accuracy | Category Recall | Origin Leakage |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN (Standard)** | 15 | 0 | 2 | 13 | 0 | 86.7% | N/A | 0.0% |
| **BENIGN_SUSPICIOUS_TOKENS** | 16 | 0 | 13 | 3 | 0 | **18.8%** | N/A | 0.0% |
| **SQLI (Evasive)** | 5 | 5 | 0 | 0 | 0 | 100.0% | 100.0% | 0.0% |
| **SQLI_HEADER** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **TRAVERSAL (Encoded)** | 5 | 4 | 0 | 0 | 1 | 80.0% | 80.0% | 20.0% |
| **CMDI (Obfuscated)** | 4 | 3 | 0 | 0 | 1 | 75.0% | 75.0% | 25.0% |
| **CMDI_HEADER (Shellshock)**| 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **SSTI (Template Injection)** | 2 | 0 | 0 | 0 | 2 | **0.0%** | **0.0%** | **100.0%** |
| **NOSQLI (Query Injection)** | 2 | 0 | 0 | 0 | 2 | **0.0%** | **0.0%** | **100.0%** |
| **XXE (XML External Entity)**| 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **LDAP_INJECTION** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **LOG4J_JNDI** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **CRED_STUFF (Slow)** | 2 | 0 | 0 | 0 | 2 | **0.0%** | **0.0%** | **100.0%** |
| **RECON (Stealth)** | 4 | 4 | 0 | 0 | 0 | 100.0% | 100.0% | 0.0% |
| **MALFORMED (Benign Safety)**| 6 | 0 | 0 | 6 | 0 | 100.0% | N/A | 0.0% |
| **MALFORMED_ATTACK** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **GRAPHQL_PROBE** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **WEBDAV_PROBE** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **XSS (Obfuscated)** | 1 | 0 | 0 | 0 | 1 | **0.0%** | **0.0%** | **100.0%** |
| **Total / Overall** | **70** | **16** | **15** | **22** | **17** | **54.3%** | **48.5%** | **51.5%** |

---

### 4.2 Failure Mode 1: False Diversions on Benign Sensitive Tokens

**Root Cause:** The feature extraction pipeline computes a single global metric `suspicious_keyword_count` by searching for substrings (`admin`, `union`, `select`, `cmd`, `passwd`, `.env`, `wp-`, `install`) across the URI path, query parameters, and body.

When a legitimate user queries documentation (`/api/search?q=how+to+use+sql+union+in+queries`), fetches a graphic asset (`/assets/admin-dashboard-preview.png`), or views a knowledge-base article (`/api/help/articles/admin-password-reset`), the keyword count increases. The scikit-learn anomaly model maps this feature to an anomaly probability of $\sim 0.92$, triggering diversion to deception.

**Evidence:**
- 13 out of 16 `BENIGN_SUSPICIOUS_TOKENS` scenarios were falsely diverted.
- In contrast, Variant B (Rules Only) diverted only 3, achieving **84.2% precision** because its deterministic rule controller requires multiple co-occurring indicators rather than scalar anomaly amplification.

---

### 4.3 Failure Mode 2: Origin Leakage on Evasive & Unseen Attack Templates

**Root Cause:**
1. **Double Encoding:** Payloads such as `%252e%252e%252f` decode only once during single-pass URI decoding to `%2e%2e%2f`. The keyword matcher failed to recognize the traversal sequence, allowing the request to pass to the origin.
2. **Alternative Injection Delimiters:** In command injection, replacing spaces or semicolons with newline characters (`%0Aid` or `cat$IFS/etc/passwd`) evaded the regex heuristics.
3. **Unseen Injection Grammars:** Payloads for Server-Side Template Injection (`{{7*7}}`), NoSQL Injection (`{"$where": "sleep(5000)"}`), XML External Entity (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`), LDAP injection (`*(|(mail=*))`), and Log4j (`${jndi:ldap://...}`) do not share vocabulary with standard SQL or Bash commands and were completely missed by the baseline model.
4. **Header Injections:** Injections placed strictly in HTTP headers (`User-Agent: () { :; }; /bin/cat /etc/passwd` or `X-Forwarded-For: 127.0.0.1' UNION SELECT NULL--`) bypassed path-centric inspection.

---

## 5. Microsecond Latency Decomposition & Stability

Previous reports stated sub-millisecond latencies as `0.000 ms` due to integer millisecond rounding. We upgraded all latency measurement to `time.perf_counter_ns()`, reporting microsecond-accurate metrics.

### 5.1 Latency Breakdown by Architecture Variant

| Variant | Architecture | p50 Gateway Latency | p95 Gateway Latency | p50 Detection Latency |
| :--- | :--- | :---: | :---: | :---: |
| **B1** | Direct Passthrough | 0.2 µs | 0.5 µs | N/A |
| **B2** | Static Substring Heuristic | 0.4 µs | 0.7 µs | 0.3 µs |
| **B3** | Regex Adaptive Routing | 0.003 ms (3.0 µs) | 0.006 ms | 0.002 ms |
| **Variant B** | Rules-Only Policy (No ML) | **0.015 ms (15.2 µs)** | 0.024 ms | **0.015 ms** |
| **Variant A** | Full Proposed Gateway (B4) | **15.912 ms** | 18.234 ms | **15.911 ms** |

> **Key Observation:** The scikit-learn pipeline (StandardScaler + RandomForest inference) accounts for **99.9%** of the gateway's total decision latency ($15.91\text{ ms}$ vs. $0.015\text{ ms}$).

### 5.2 Multi-Run Stability (5 Random Seeds)
To verify that inference timings are statistically stationary and not distorted by JIT warm-up or CPU throttling, 5 repetitions were executed with seeds `[42, 101, 202, 303, 404]`:

$$\text{Latency (p50)} = 14.325\text{ ms} \pm 1.136\text{ ms} \quad (\text{Min: } 12.914\text{ ms}, \text{ Max: } 16.038\text{ ms})$$

---

## 6. Deception Effectiveness Score (DES) Formal Reconciliation

The Deception Effectiveness Score (DES) evaluates the containment capability of the dynamic deception runtime using an evidence-based formulation:

$$\text{DES} = \mathbb{I}[L_{\text{leak}} = 0] \cdot \left( 0.30 \cdot D_{\text{depth}} + 0.30 \cdot C_{\text{consistency}} + 0.25 \cdot T_{\text{dwell}} + 0.15 \cdot E_{\text{engagement}} \right)$$

### 6.1 Reconciliation of Reported Values:

1. **Held-Out Test Set (DES = 0.925):**
   - Origin Leaks: $L_{\text{leak}} = 0 \implies \mathbb{I}[L=0] = 1.0$
   - DSG Node Depth: 3 of 4 states visited (`DISCOVERY`, `RECONNAISSANCE`, `EXPLOITATION_ATTEMPT`) $\implies D_{\text{depth}} = 3/4 = 0.750 \implies 0.30 \times 0.750 = \mathbf{0.225}$
   - State Consistency: 30 of 30 synthetic responses generated $\implies C_{\text{consistency}} = 1.000 \implies 0.30 \times 1.000 = \mathbf{0.300}$
   - Attacker Dwell: 30 interactions against target of 10 $\implies T_{\text{dwell}} = 1.000 \implies 0.25 \times 1.000 = \mathbf{0.250}$
   - Decoy Engagement: 20 decoy interactions touched $\implies E_{\text{engagement}} = 1.000 \implies 0.15 \times 1.000 = \mathbf{0.150}$
   - **Total:** $0.225 + 0.300 + 0.250 + 0.150 = \mathbf{0.925}$

2. **Combined Benchmark Set (DES = 1.000):**
   - All 4 DSG states were explored (`CREDENTIAL_ACCESS` included in dev split) $\implies D_{\text{depth}} = 4/4 = 1.000 \implies 0.30 \times 1.000 = \mathbf{0.300}$.
   - **Total:** $0.300 + 0.300 + 0.250 + 0.150 = \mathbf{1.000}$.

3. **Adversarial Robustness Set (DES = 0.000):**
   - 17 evasive attacks reached the origin ($L_{\text{leak}} = 17$).
   - The binary gate enforced $\mathbb{I}[L=0] = 0.0$, collapsing the total score to **0.000**.

---

## 7. Threats to Scientific Validity

1. **Synthetic Data Dependency:** Both the training corpus and benchmark scenarios are generated from controlled synthetic grammars. True real-world attacker distributions contain unpredictable mixtures of automated fuzzing, multi-stage human reconnaissance, and bespoke payloads.
2. **In-Process Pipeline Mocking:** Benchmark evaluation was executed in a unified Python runtime to measure algorithmic decision boundaries without network jitter. While accurate for inference comparison, physical network proxies introduce TCP buffering, connection resets, and TLS handshake latency.
3. **Session Replay Assumptions:** Scenarios simulate session sequences linearly. Real-world adversaries frequently switch source IP addresses, user agents, and proxy nodes to evade session correlation.

---

## 8. Engineering Roadmap for Production Hardening

Based on the empirical findings of this ablation study, the following enhancements are prioritized for future stages:

1. **Context-Aware AST Tokenization:** Replace bag-of-words string searches with Abstract Syntax Tree (AST) parsers for SQL, Shell, and JSON. A query parameter `q=sql union tutorial` should be parsed as English prose rather than SQL tokens.
2. **Recursive Canonicalization:** Decode input buffers repeatedly until a fixed point is reached to defeat multi-layered URI and hexadecimal encoding (`%252e%252e%252f` $\to$ `%2e%2e%2f` $\to$ `../`).
3. **Hybrid Two-Tier Scoring:** Retain Variant B's ultra-low latency ($15\text{ µs}$) as a primary filter. Only invoke heavy ML inference ($15\text{ ms}$) when deterministic rules identify ambiguous or borderline signals ($0.30 \le \text{risk} \le 0.70$).
4. **Header and Structured Body Inspection:** Extend feature extraction beyond URI paths to cover headers (`User-Agent`, `Referer`, `Authorization`) and nested payload bodies (XML, JSON, YAML).
