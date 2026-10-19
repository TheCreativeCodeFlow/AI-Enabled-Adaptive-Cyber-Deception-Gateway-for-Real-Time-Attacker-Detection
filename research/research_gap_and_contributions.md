# Research Gap, Contributions, and Scientific Hypotheses

> **Document Type:** Scientific Framing, Defensible Research Gap, and Hypotheses  
> **Project:** AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection  
> **Repository Commit:** `fa9960205ecc00a952b3f64bdf1125b608d8370b`  
> **Status:** Stage 12 Research Definition  

---

## 1. Problem Statement

Modern enterprise web applications operate in an asymmetric threat landscape. Persistent adversaries systematically execute multi-stage reconnaissance, parameter tampering, and injection exploits (e.g. SQLi, CMDi, Path Traversal, SSRF) against public-facing application endpoints. Traditional defensive paradigms exhibit well-documented structural deficiencies:

1. **Perimeter Firewalls and WAFs:** Rely predominantly on static signature matching or heuristic thresholding. While effective against known, verbatim payloads, they are easily bypassed by obfuscated or novel exploit templates. When configured aggressively, they produce high false-positive rates that disrupt legitimate business transactions.
2. **Traditional Honeypots:** Typically deployed on isolated dark subnets or unadvertised IP spaces. Because they are physically separated from authentic production workflows, they fail to detect or capture targeted attacks directed specifically at authorized application endpoints.
3. **Network-Layer Moving Target Defenses (MTD):** Existing dynamic deception and MTD systems operate predominantly at Layer 3/Layer 4 using Software-Defined Networking (SDN) or OpenFlow switches. These architectures require specialized network hardware, introduce flow-table scaling limits, and cannot inspect or maintain context over Layer-7 HTTP application semantics (e.g., cookies, JSON bodies, authentication headers).

Consequently, there is an urgent research need for a **lightweight, Layer-7 reverse proxy gateway** that operates inline in front of production web services, evaluates incoming requests via machine-learning anomaly scoring, and adaptively diverts malicious sessions into isolated, stateful synthetic honeypots while maintaining session continuity and zero origin leakage.

---

## 2. Documented Limitations of Existing Approaches (Directly Supported by Literature)

The research gap addressed by this project is established by specific, documented limitations in prior literature:

### 2.1 Limitation 1: False Positive Disruption in Pure Anomaly Detection
- **Literature Evidence:** As demonstrated by **Anagnostakis et al. (2005)**, **Kruegel & Vigna (2003)**, and **Robertson et al. (2006)**, statistical anomaly detection on HTTP requests inevitably triggers false alarms when benign users submit novel or complex inputs. In an inline blocking architecture, false positives directly cause denial of service for legitimate users.
- **Project Observation:** In our Stage 10 adversarial robustness evaluation, benign requests containing benign SQL keywords (e.g., searching for products with words like `UNION` or `SELECT`) triggered an unacceptable **40.5% False Positive Rate** when evaluated by the raw ML classifier alone.

### 2.2 Limitation 2: Evasion Under Novel Encodings and Payloads
- **Literature Evidence:** Supervised classifiers and tree-based ensembles overfit to training syntactic distributions and fail against zero-day evasion techniques (**Torrano-Giménez et al. 2010**, **Han et al. 2018**).
- **Project Observation:** On the 70-scenario adversarial robustness dataset, novel injection templates and double-encoded payloads produced a **51.5% False Negative Rate** in the ML model, proving that machine learning alone cannot be trusted as an unassisted security gate.

### 2.3 Limitation 3: Computational Intractability of Game-Theoretic Deception
- **Literature Evidence:** While theoretical frameworks model cyber deception as partially observable Markov games or hypergames (**Pawlick et al. 2019**, **Sengupta et al. 2020**), calculating dynamic Nash or Stackelberg equilibria across real-time network states suffers from the curse of dimensionality and is computationally infeasible within microsecond web reverse-proxy latency budgets.
- **Project Resolution:** Replacing dynamic game equilibrium computation with a deterministic, lightweight finite-state Deception State Graph (DSG) bound by an immutable Protected Policy Layer.

### 2.4 Limitation 4: Absence of Leakage-Gated Deception Metrics
- **Literature Evidence:** Honeypot and deception metrics historically measured raw hits, connection counts, or attacker dwell time (**Ferguson-Walter et al. 2021**). However, prior evaluation frameworks fail to formalize the relationship between deception engagement and origin defense: a honeypot that engages an attacker for hours is completely ineffective if the attacker simultaneously accesses production data.
- **Project Resolution:** The mathematical formulation of the Deception Effectiveness Score (DES) incorporates a binary zero-leakage gate $\mathbb{I}[L_{\text{leak}} = 0]$, penalizing any system that permits even a single malicious request to reach the origin.

### 2.5 Limitation 5: Infrastructure Overhead of Network-Layer Diversion
- **Literature Evidence:** Existing dynamic diversion patents and academic prototypes rely heavily on SDN OpenFlow switches, TCP sequence rewrites, or IP address cloning ([PAT-01], [PAT-08], **Cho et al. 2020**). These mechanisms cannot run in standard containerized or cloud-native microservice environments without specialized kernel privileges.
- **Project Resolution:** Implementing selective diversion entirely within an application-layer (L7) HTTP reverse proxy utilizing standard HTTP cookies, headers, and reverse proxy forwarding.

---

## 3. Defensible Technical Contributions (Separated from Prior Art)

To maintain scientific integrity, we explicitly distinguish established prior art from the actual technical contributions of this project:

```
+-----------------------------------------------------------------------------------+
|                            ESTABLISHED PRIOR ART                                  |
| - Inline HTTP Reverse Proxying (Standard Web Art: NGINX, HAProxy, Envoy)          |
| - HTTP Request Anomaly Feature Extraction (Kruegel & Vigna 2003, Robertson 2006)  |
| - Selective Anomaly-Triggered Traffic Diversion (Anagnostakis et al. 2005)        |
| - Dynamic Honeypot Redirection via SDN Flow Tables (Acalvio US 10,193,924)       |
| - Attacker Dwell Time as a Deception Efficacy Metric (Ferguson-Walter et al. 2021)|
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     ACTUAL DEFENSIVE TECHNICAL CONTRIBUTIONS                     |
|                                                                                   |
| 1. L7 Multi-Tenant Reverse Proxy with Cryptographic DNS TXT Onboarding            |
| 2. Hybrid Decision Pipeline with Intermediate 'OBSERVE_ONLY' Origin Forwarding   |
| 3. In-Memory Sticky Session Pinning for Multi-Turn Attacker Containment           |
| 4. Containerized Deception State Graph (DSG) with Protected Policy Boundaries     |
| 5. Evidence-Based Deception Effectiveness Score (DES) with Binary Leakage Gate    |
| 6. Fully Versioned, Reproducible Multi-Variant Research Evaluation Framework      |
+-----------------------------------------------------------------------------------+
```

### Detailed Contribution Breakdown

#### Contribution 1: Layer-7 Multi-Tenant Deception Gateway
An application-layer reverse proxy that integrates multi-tenant organization workspaces, cryptographic domain verification (DNS TXT challenges), and tenant-isolated routing configurations. It enforces strict request validation, body size caps, and timing-safe operator authentication without requiring specialized SDN or network-layer switch hardware.

#### Contribution 2: Hybrid Anomaly Decision Pipeline with Intermediate State
A hybrid scoring architecture that couples a serialized random forest model (trained on request-level entropy, length, and syntactic token features) with deterministic regex fast-paths. Crucially, the decision controller introduces a three-way routing outcome:
- `ORIGIN`: Benign evaluation ($score < 0.40$).
- `OBSERVE_ONLY`: Ambiguous evaluation ($0.40 \le score < 0.70$), forwarding traffic to the legitimate origin to prevent business disruption while recording telemetry and escalating session suspicion.
- `DECEPTION`: High-confidence malicious evaluation ($score \ge 0.70$), triggering immediate diversion to the honeypot.

#### Contribution 3: Stateful Session Router and Containment Pinning
An in-memory session routing store with a sliding TTL (30 minutes). Once a session identifier (`sessionId`) is diverted to deception, all subsequent requests within that session are pinned to `target: 'DECEPTION'` with reason `'STICKY_SESSION_ASSIGNMENT'`. This prevents multi-turn attackers from probing decoys and then slipping follow-up exploits back to the legitimate origin.

#### Contribution 4: Containerized Deception State Graph (DSG) with Protected Policy Layer
A lightweight 4-node finite state machine (`RECONNAISSANCE` $\rightarrow$ `DISCOVERY` $\rightarrow$ `EXPLOITATION` $\rightarrow$ `CREDENTIAL_ACCESS`) operating inside an isolated, unexposed container. Transitions are governed by an immutable Protected Policy Layer that allowlists valid synthetic REST endpoints (`/api/catalog`, `/api/users`, `/api/files`, `/api/auth/login`) and enforces realistic JSON schemas, preventing host filesystem access or honeypot escape.

#### Contribution 5: Mathematically Gated Deception Effectiveness Score (DES)
A formal metric quantifying defensive performance based on observed empirical outcomes:
$$\text{DES} = \mathbb{I}[L_{\text{leak}} = 0] \cdot \left(0.30 \cdot D_{\text{depth}} + 0.30 \cdot C_{\text{consistency}} + 0.25 \cdot T_{\text{dwell}} + 0.15 \cdot E_{\text{engagement}}\right)$$
The score incorporates traversal depth ($D$), response consistency ($C$), dwell interactions ($T$), and decoy breadth ($E$). The binary indicator $\mathbb{I}[L_{\text{leak}} = 0]$ strictly enforces that any origin leak collapses the score to $0.000$, formalizing containment as a prerequisite for deception value.

#### Contribution 6: Multi-Variant Research Evaluation Framework
A local, versioned, and reproducible benchmark framework that executes comparative evaluations across 4 baselines (B1–B4) and 4 architectural ablation variants (A–D) against three distinct datasets (Standard Benchmark v1, Adversarial Robustness v1, and External Public Benchmark v1).

---

## 4. Testable Research Questions and Hypotheses

To guide future experimental extensions and peer review, the technical contributions are formalized into three testable research questions ($RQ$) and hypotheses ($H$):

### Research Question 1 (RQ1): Cross-Dataset Generalization & Containment Efficacy
*Does an integrated Layer-7 anomaly deception gateway achieve significantly higher attack containment than static heuristic and regex-only baselines when evaluated on un-tuned external HTTP security datasets?*

- **Hypothesis 1 ($H_1$):** On the un-tuned external public benchmark (100 scenarios from CSIC 2010 and OWASP CRS), the full proposed gateway (Variant A / B4) will achieve an absolute attack recall gain of at least **+20.0%** over the rule-based baseline (Variant B / B3) while maintaining a False Positive Rate ($FPR$) below **5.0%**.
- **Empirical Status:** **Confirmed.** In Stage 11 empirical evaluation:
  - Variant B (Rules Only): Recall = 46.0% (23/50), Origin Leaks = 27/50 (54.0%), FPR = 0.0%.
  - Variant A (Full Proposed): Recall = 74.0% (37/50), Origin Leaks = 13/50 (26.0%), FPR = 0.0%.
  - Absolute Recall Gain: **+28.0%** ($74.0\% - 46.0\%$) with **0.0% False Positive Rate**.

### Research Question 2 (RQ2): The Role of Session Stickiness in Threat Containment
*Does disabling session stickiness significantly degrade threat containment during multi-request attacker sessions?*

- **Hypothesis 2 ($H_2$):** In multi-probe attacker campaigns where an initial injection is followed by low-entropy reconnaissance probes, disabling session stickiness (Variant D) will cause a statistically significant increase in origin leakage compared to sticky stateful routing (Variant A).
- **Empirical Status:** **Confirmed.** In Stage 10.1 audit on the multi-turn held-out test split:
  - Variant A (Sticky Session Routing): 0 origin leaks ($0.0\%$), Recall = 100.0%, DES = 0.925.
  - Variant D (Stateless Routing): 6 origin leaks ($20.0\%$), Recall = 80.0%, DES = 0.000.
  - Session stickiness prevented 6 multi-turn attack probes from leaking back to production origin.

### Research Question 3 (RQ3): Inline Gateway Latency Overhead
*Can an integrated hybrid ML anomaly scoring and session routing gateway operate within the acceptable p50 latency threshold (< 20 ms) of enterprise web applications?*

- **Hypothesis 3 ($H_3$):** Across repeated evaluation trials and varying random seeds, the median gateway forwarding latency (including feature extraction, ML inference, and session policy lookup) will not exceed **20.0 ms**.
- **Empirical Status:** **Confirmed.** Across 5 independent seed runs (`[42, 101, 202, 303, 404]`):
  - Observed p50 Latency: **13.620 ms $\pm$ 0.030 ms** (Min: 13.577 ms, Max: 13.661 ms).
  - Well below the 20.0 ms budget and enterprise interactive web latency targets (< 100 ms).

---

## 5. Claims Supported by Empirical Evidence vs. Unproven Scope Boundaries

A core requirement of rigorous research is explicitly delineating verified empirical claims from unproven assumptions.

### 5.1 Claims Supported by Current Experiments

| Area | Experimentally Supported Claim | Supporting Verification Artifact |
| :--- | :--- | :--- |
| **Standard Containment** | Variant A achieves **100.0% recall, 0 origin leaks**, and **DES = 0.925** on the 60-sample held-out synthetic test set. | `reports/evaluation_results.json` |
| **Cross-Dataset Robustness**| Variant A achieves **74.0% recall, 100.0% precision, 87.0% accuracy**, and **13/50 origin leaks** on the 100-sample external benchmark (CSIC 2010 + OWASP CRS). | `reports/external_benchmark_results.json` |
| **Ablation Superiority** | Variant A outperforms the Rules-Only baseline (Variant B) by **+28.0% absolute recall** on un-tuned external traffic. | `reports/external_benchmark_evaluation.md` |
| **Session Stickiness Value** | Disabling session stickiness reduces recall by **20.0%** and causes **6 origin leaks** on multi-turn synthetic attack sessions. | `reports/ablation_and_robustness_results.json` |
| **Microsecond Latency Stability**| The gateway introduces **13.620 ms $\pm$ 0.030 ms** p50 latency across multiple random seed repetitions. | `reports/robustness_and_ablation_study.md` |
| **Codebase Verification**| All 157 automated test assertions pass across gateway, backend, deception, and detection services. | Test suites (Jest, Tsx, Pytest) |

### 5.2 Claims That Remain Unproven (Explicit Scope Boundaries & Limitations)

The following claims are **not supported** by the current experiments and must not be asserted without future research:

1. **Live-Production Generalization:** The system has not been tested against real-world, high-volume production network traffic. While the external benchmark contains real HTTP queries from CSIC 2010 and OWASP CRS, these represent automated testbeds and security regression tests, not live human production sessions.
2. **Human Attacker Engagement:** The Deception State Graph (DSG) has been evaluated against automated Python scripts and testbed scanner probes. Its ability to deceive and maintain the dwell time of a skilled, interactive human red-team operator remains unproven.
3. **Robustness Under Adaptive Adversarial Evasion:** The Stage 10 adversarial robustness evaluation revealed that novel injection templates and double-encoded payloads cause a **51.5% False Negative Rate**. The current model is vulnerable to targeted adversarial evasion if an attacker knows the feature schema.
4. **Autonomous AI Optimization:** The strategy selector and policy controller operate on deterministic heuristic rules and threshold comparisons. The project does not implement dynamic reinforcement learning (RL) or autonomous game-theoretic equilibrium solving.
5. **Distributed Scalability:** The current session store is implemented in-memory in a single Node.js process. Scalability across a distributed, clustered reverse proxy fleet (e.g. Redis-backed session replication) has not been empirically benchmarked.

---

## 6. Conclusion and Future Research Roadmap

The AI-Enabled Adaptive Cyber Deception Gateway demonstrates a defensible research niche: it bridges the gap between theoretical game-theoretic deception and static network-layer honeypots by providing a practical, application-layer reverse proxy platform. 

Future research should focus on:
1. **Adversarial Hardening:** Retraining the anomaly model on multi-layer encoded injection payloads to reduce the 51.5% adversarial FNR.
2. **Distributed Session Storage:** Implementing Redis-backed distributed session stickiness for multi-cluster enterprise deployments.
3. **Human Red-Team Validation:** Conducting controlled red-team trials modeled after the Tularosa Study (Ferguson-Walter et al.) to measure real human attacker dwell time and psychological deception efficacy.
