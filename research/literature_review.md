# Research Literature Review: Adaptive Cyber Deception, Web Anomaly Detection, and Threat Containment

> **Document Type:** Research Literature Review & State-of-the-Art Analysis  
> **Project:** AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection  
> **Repository Commit:** `fa9960205ecc00a952b3f64bdf1125b608d8370b`  
> **Date of Search:** October 19, 2026  
> **Status:** Stage 12 Research Literature Review (Fully Verified Citations & Traceable DOIs)  

---

## 1. Executive Summary & Review Scope

This document provides a comprehensive, rigorous literature review evaluating the academic foundations of the **AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection**. The project investigates a hybrid Layer-7 reverse proxy architecture that couples machine-learning anomaly scoring with policy-controlled adaptive cyber deception. 

To rigorously assess where this work sits in relation to prior scholarship, this review examines ten canonical peer-reviewed works spanning six core thematic areas:
1. **Selective Traffic Diversion & Shadow Honeypots**
2. **HTTP Request-Level Anomaly Detection & Feature Extraction**
3. **Game-Theoretic Modeling & Deceptive State Transitions**
4. **Empirical Deception Efficacy, Attacker Dwell Time & Metrics**
5. **Moving Target Defense (MTD) & Dynamic Attack Surface Mutation**
6. **Web Honeypot Emulation, Protocol Consistency & Anti-Fingerprinting**

All included citations have been verified against academic databases (ACM Digital Library, IEEE Xplore, USENIX Proceedings, OpenAlex). Unverified sources, preprints without confirmed publication records, and speculative citations have been strictly excluded.

---

## 2. Thematic Analysis of Prior Research

### 2.1 Theme 1: Selective Traffic Diversion & Shadow Honeypots
The concept of placing an inspection gateway in front of production systems and diverting only suspicious traffic into a deceptive environment was pioneered by **Anagnostakis et al. (USENIX Security 2005)** in their seminal *Shadow Honeypots* architecture. Anagnostakis et al. addressed the fundamental trade-off of anomaly detection: high false positive rates make direct inline blocking dangerous, while standard honeypots sitting on dark subnets never process targeted production traffic. Their solution was to split incoming traffic—benign requests proceed directly to the production server, while requests flagged as anomalous are mirrored to an instrumented "shadow" instance that mirrors the internal memory state of the production process. If the shadow crashes or exhibits malicious behavior, the attack is aborted; if the shadow executes normally (a false alarm), the state changes are merged and the response is transparently returned to the user.

*Direct Relevance to Project:* This project inherits the core architectural principle of selective anomaly-triggered diversion. However, whereas shadow honeypots require complex runtime memory cloning and rollbacks of the actual production binary to handle false positives, this project routes traffic at Layer 7 to independent containerized synthetic mock services, and explicitly establishes that any attack request taking the `OBSERVE_ONLY` fallback path to the real origin constitutes an **Origin Leak** ($FN$).

### 2.2 Theme 2: HTTP Anomaly Detection & Parameter Feature Engineering
Machine learning and statistical anomaly detection for web applications have been studied extensively since the early 2000s. **Kruegel & Vigna (ACM CCS 2003)** established multi-model anomaly detection for HTTP queries, evaluating attribute length distributions, character entropy (variance of character distribution), structural token ordering, and parameter presence. **Robertson et al. (NDSS 2006)** extended this work by introducing generalization techniques that characterize web parameter profiles and eliminate false alarms caused by natural benign parameter variations. **Torrano-Giménez et al. (2010)** created the HTTP Dataset CSIC 2010, systematically executing web vulnerability scanners (Paros, Nessus) and synthetic crawler scripts against an experimental e-commerce web application (`tienda1`) to produce structured anomalous and normal HTTP transaction traces.

*Direct Relevance to Project:* The feature extraction engine (`detection/src/ml_model.py` and `gateway/src/features.ts`) implements the exact feature families established by Kruegel & Vigna: URI length, special character ratios, Shannon entropy, keyword density, and parameter distributions. The empirical evaluation in Stage 11 builds directly upon Torrano-Giménez et al.'s CSIC 2010 dataset. However, modern evaluation reveals that static anomaly models suffer when exposed to unseen encoding or modern REST API structures (exhibiting 26% origin leakage on CSIC 2010 + OWASP CRS), demonstrating why anomaly detection alone cannot guarantee containment without session-aware policy gating.

### 2.3 Theme 3: Game-Theoretic Cyber Deception & State Modeling
Cyber deception has evolved from static traps to formal mathematical games of incomplete information. **Pawlick, Colbert, & Zhu (ACM Computing Surveys 2019)** synthesized defensive deception into a comprehensive taxonomy covering signaling games, hypergames, and partially observable Markov decision processes (POMDPs). In these models, a defender strategically sends deceptive signals (e.g. fake assets, altered responses) to manipulate the attacker's posterior beliefs regarding the network state. The attacker's progression is frequently modeled over attack graphs, where transitions depend on successful privilege escalation or vulnerability exploitation.

*Direct Relevance to Project:* The Deception State Graph (DSG) implemented in `deception/src/dsg.ts` operates as a practical, deterministic abstraction of an attack graph. It models four operational attacker phases (`RECONNAISSANCE` $\rightarrow$ `DISCOVERY` $\rightarrow$ `EXPLOITATION` $\rightarrow$ `CREDENTIAL_ACCESS`). However, while game-theoretic literature focuses on solving optimal mixed-strategy Nash or Stackelberg equilibria, this project implements a rule-based Protected Policy Layer that guarantees deterministic containment constraints rather than computing dynamic equilibrium strategies.

### 2.4 Theme 4: Empirical Deception Metrics & Attacker Dwell Time
For decades, honeypot research lacked standardized, empirical efficacy metrics beyond raw connection counts. **Ferguson-Walter et al. (HICSS 2019, USENIX Security 2021)** conducted the landmark *Tularosa Study*, subjecting over 130 professional red teamers to multi-day penetration tests across networks with varying levels of cyber and psychological deception. Their findings proved empirically that:
1. Attackers spend **up to 3.5 times more time** on decoys than on real operational hosts.
2. Psychological priming (awareness that deception is present) induces cognitive paralysis, slows planning, and degrades task completion rates.
3. Dwell time on decoys and the number of unforced attacker errors are the primary quantifiable metrics of deception success.

*Direct Relevance to Project:* The mathematical formulation of the Deception Effectiveness Score (DES) implemented in `gateway/src/des.ts` directly operationalizes Ferguson-Walter's findings:
$$\text{DES} = \mathbb{I}[L_{\text{leak}} = 0] \cdot \left(0.30 \cdot D_{\text{depth}} + 0.30 \cdot C_{\text{consistency}} + 0.25 \cdot T_{\text{dwell}} + 0.15 \cdot E_{\text{engagement}}\right)$$
The score incorporates dwell time ($T_{\text{dwell}}$), decoy interaction breadth ($E_{\text{engagement}}$), and graph traversal depth ($D_{\text{depth}}$). Crucially, the project introduces a strict binary gate $\mathbb{I}[L_{\text{leak}} = 0]$: if any malicious request leaks to the origin, the score collapses to $0.000$, enforcing that deception without containment has zero defensive utility.

### 2.5 Theme 5: Moving Target Defense & Dynamic Surface Mutation
Moving Target Defense (MTD) creates dynamic asymmetry by continuously shifting system configurations. **Cho et al. (IEEE COMST 2020)** and **Sengupta et al. (IEEE COMST 2020)** surveyed MTD paradigms across networks, software, and data. They categorized techniques into dynamic runtime address shuffling, virtual machine migration, and software-defined network (SDN) flow manipulation. **Han, Kheir, & Balzarotti (ACM Computing Surveys 2018)** provided a systematic perspective on cyber deception, emphasizing that dynamic deception environments must preserve cross-layer consistency (e.g., protocol timing, MAC/IP parity, file timestamps) to prevent attackers from fingerprinting the deception layer.

*Direct Relevance to Project:* While traditional MTD mutates the legitimate production attack surface, this project leaves the production origin stable and instead mutates the *perceived* surface at the reverse proxy. By enforcing session stickiness (`sessionRouter.ts`) and allowlisted synthetic data schemas (`syntheticData.ts`), the project addresses Han et al.'s consistency requirement, preventing multi-turn attackers from detecting state discrepancies between requests.

### 2.6 Theme 6: Web Honeypot Emulation & Fingerprinting Resilience
Low-interaction web honeypots such as Glastopf and early PHP traps were notoriously easy for attackers to identify due to static response bodies, missing header nuances, and predictable error messages. **Vetterl & Clayton (IEEE eCrime 2019)** introduced *Honware*, demonstrating that effective capture of zero-day web exploits requires high-fidelity emulation of dynamic application workflows. Modern web deception frameworks (e.g. SNARE and TANNER) separate the lightweight HTTP sensor from an intelligent backend evaluation engine to deliver realistic responses.

*Direct Relevance to Project:* The deception runtime (`deception/src/`) functions as a dedicated application-layer sensor. It implements realistic mock routes (`/api/catalog`, `/api/users`, `/api/files`, `/api/auth/login`) that respond with structurally valid JSON schemas, realistic authentication delays, and synthetic credential challenges, avoiding the trivial fingerprinting pitfalls of legacy static honeypots.

---

## 3. Traceable Inventory of Canonical Scholarly Sources

The following ten works constitute the verified core scientific foundation:

```
[LIT-01] Anagnostakis et al. (2005) — "Detecting Targeted Attacks Using Shadow Honeypots" (USENIX Security)
[LIT-02] Kruegel & Vigna (2003) — "Anomaly Detection of Web-based Attacks" (ACM CCS)
[LIT-03] Pawlick, Colbert, & Zhu (2019) — "A Game-Theoretic Taxonomy and Survey of Defensive Deception" (ACM CSUR)
[LIT-04] Ferguson-Walter et al. (2021) — "Examining the Efficacy of Decoy-based and Psychological Deception" (USENIX Security)
[LIT-05] Han, Kheir, & Balzarotti (2018) — "Deception Techniques in Computer Security: A Research Perspective" (ACM CSUR)
[LIT-06] Cho et al. (2020) — "Toward Proactive, Adaptive Defense: A Survey on Moving Target Defense" (IEEE COMST)
[LIT-07] Sengupta et al. (2020) — "A Survey of Moving Target Defenses for Network Security" (IEEE COMST)
[LIT-08] Torrano-Giménez et al. (2010) — "An anomaly-based approach for intrusion detection in web traffic" (JIAS)
[LIT-09] Vetterl & Clayton (2019) — "Honware: A Virtual Honeypot Framework for Capturing CPE and IoT Zero Days" (IEEE eCrime)
[LIT-10] Robertson et al. (2006) — "Using Generalization and Characterization to Detect Web-Based Attacks" (NDSS)
```

### Detailed Source Analysis

#### Source 1: [LIT-01] Anagnostakis et al. (2005)
- **Full Citation:** Anagnostakis, K. G., Sidiroglou, S., Akritidis, P., Xinidis, K., Markatos, E., & Keromytis, A. D. (2005). Detecting Targeted Attacks Using Shadow Honeypots. In *Proceedings of the 14th USENIX Security Symposium (USENIX Security 05)*, pp. 129–144, Baltimore, MD, USA.  
- **Stable URL:** [USENIX Event Archive](https://www.usenix.org/conference/14th-usenix-security-symposium/detecting-targeted-attacks-using-shadow-honeypots)
- **Problem & Proposed Approach:** Anomaly-based intrusion detection systems suffer from high false-positive rates that disrupt legitimate users if traffic is blocked inline. Pure honeypots cannot observe attacks directed at real servers. The authors proposed *Shadow Honeypots*, where an anomaly detector diverts suspicious traffic to an instrumented shadow instance sharing internal state with the live server.
- **Key Technical Mechanisms:** In-line network sensor; anomaly score thresholding; copy-on-write memory sharing between production process and shadow clone; rollback on detected exploit; transparent state commitment on benign completion.
- **Evaluation Method & Limitations:** Evaluated on Apache HTTP server and Mozilla client. Evaluated against synthetic buffer overflows and web exploits. Demonstrated up to 20% overhead on shadow processing, but minimal impact on clean traffic. Limitations: Requires heavy OS/runtime instrumentation (process cloning, memory synchronization), limited to applications where side-effects (e.g. database commits, third-party network calls) can be rolled back safely.
- **Direct Project Overlap:** Architectural archetype: inline reverse proxy inspecting inbound traffic, applying anomaly scoring, and selectively diverting suspect requests into an isolated deceptive execution environment.
- **Project Differences & Novelty:** The shadow honeypot attempts to execute the real application code with memory rollbacks. This project routes traffic at the HTTP protocol layer to independent containerized synthetic mock services governed by a Deception State Graph. Furthermore, while shadow honeypots silently pass false positives, this project measures and penalizes origin leakage when attacks receive origin or observe-only routing.

#### Source 2: [LIT-02] Kruegel & Vigna (2003)
- **Full Citation:** Kruegel, C., & Vigna, G. (2003). Anomaly Detection of Web-based Attacks. In *Proceedings of the 10th ACM Conference on Computer and Communications Security (CCS '03)*, pp. 251–261, Washington, DC, USA.  
- **DOI:** [10.1145/948109.948144](https://doi.org/10.1145/948109.948144)
- **Problem & Proposed Approach:** Traditional signature-based IDSs fail against novel web application exploits. The authors proposed multi-model anomaly detection trained on normal web requests to establish statistical baselines of acceptable HTTP parameter profiles.
- **Key Technical Mechanisms:** Analyzed four feature models: attribute length, character distribution (entropy/variance), structural token presence, and query parameter frequency.
- **Evaluation Method & Limitations:** Evaluated on DARPA 1999 IDS evaluation dataset and real-world traffic from university departmental web servers. Limitations: High false positive rate when web applications introduce new forms or legitimate large payloads; cannot maintain state across multi-request sessions.
- **Direct Project Overlap:** Direct basis for the request feature engineering pipeline (`gateway/src/features.ts` and `detection/src/main.py`), specifically URI length, entropy, special character frequency, and token matching.
- **Project Differences & Novelty:** Kruegel & Vigna used statistical heuristics for alert generation only. This project combines feature extraction with an ensemble random forest model, regex short-circuits, and feeds output directly into an active policy controller managing session diversion.

#### Source 3: [LIT-03] Pawlick, Colbert, & Zhu (2019)
- **Full Citation:** Pawlick, J., Colbert, E., & Zhu, Q. (2019). A Game-Theoretic Taxonomy and Survey of Defensive Deception for Cybersecurity and Privacy. *ACM Computing Surveys (CSUR)*, Vol. 52, Iss. 4, Article 82, pp. 1–34.  
- **DOI:** [10.1145/3337772](https://doi.org/10.1145/3337772)
- **Problem & Proposed Approach:** Lack of formal, structured categorization for defensive cyber deception techniques and strategies. The authors formulated a comprehensive game-theoretic taxonomy.
- **Key Technical Mechanisms:** Categorized deception into 6 game classes: games of incomplete information, signaling games (Bayesian belief updates), screening games, hypergames (mismatched game perceptions), and stochastic Markov games.
- **Evaluation Method & Limitations:** Theoretical and taxonomic analysis. Limitations: Equilibrium computation in large-scale Markov games suffers from the curse of dimensionality and assumes mathematical rationality in adversaries, which often fails against human red teams.
- **Direct Project Overlap:** Provides the mathematical formalism for adversary state tracking, information asymmetry, and progressive deceptive responses.
- **Project Differences & Novelty:** Pawlick et al. focus on theoretical equilibrium solutions. This project realizes a practical software implementation using a deterministic 4-node finite state machine (DSG) with fixed policy boundaries and session persistence, avoiding the computational overhead of dynamic game solving.

#### Source 4: [LIT-04] Ferguson-Walter et al. (2021)
- **Full Citation:** Ferguson-Walter, K. J., Major, M. M., Johnson, C. K., & Muhleman, D. H. (2021). Examining the Efficacy of Decoy-based and Psychological Cyber Deception. In *Proceedings of the 30th USENIX Security Symposium (USENIX Security 21)*, pp. 1127–1144.  
- **Stable URL:** [USENIX Event Archive](https://www.usenix.org/conference/usenixsecurity21/presentation/ferguson-walter) | **ISBN:** 978-1-939133-24-3
- **Problem & Proposed Approach:** Cybersecurity lacks rigorous empirical evidence on whether deception actually impacts human adversary behavior. The authors designed and executed *The Tularosa Study* to measure how decoys and psychological priming affect red-team operations.
- **Key Technical Mechanisms:** Controlled red-team experiments across 130+ professional operators; tracking time spent on decoy vs real hosts; measuring unforced errors, reconnaissance efficiency, and task progression.
- **Evaluation Method & Limitations:** Multi-day network penetration testing in realistic enterprise testbed environments. Limitations: Extremely resource-intensive human study; focused on network/host lateral movement rather than web application reverse proxying.
- **Direct Project Overlap:** Direct empirical justification for dwell time ($T_{\text{dwell}}$) and decoy engagement ($E_{\text{engagement}}$) metrics within the Deception Effectiveness Score (DES).
- **Project Differences & Novelty:** Ferguson-Walter et al. measured offline human psychological outcomes across subnets. This project operationalizes these insights into an automated mathematical scoring function evaluated inline at a web application gateway.

#### Source 5: [LIT-05] Han, Kheir, & Balzarotti (2018)
- **Full Citation:** Han, X., Kheir, N., & Balzarotti, D. (2018). Deception Techniques in Computer Security: A Research Perspective. *ACM Computing Surveys (CSUR)*, Vol. 51, Iss. 4, Article 80, pp. 1–36.  
- **DOI:** [10.1145/3214305](https://doi.org/10.1145/3214305)
- **Problem & Proposed Approach:** Comprehensive survey classifying defensive deception across system layers and identifying core operational challenges in deception deployment.
- **Key Technical Mechanisms:** Categorized deception into decoy systems, deceptive data objects (honeytokens), and active deception orchestration. Formulated the *Consistency Principle*: deceptive systems must present coherent temporal, protocol, and data states to avoid detection.
- **Evaluation Method & Limitations:** Literature analysis covering 15+ years of deception research. Limitations: Survey paper; does not introduce an empirical software prototype.
- **Direct Project Overlap:** Guides the architectural requirement for strict consistency between deception policy, virtual states, and observed attacker sessions.
- **Project Differences & Novelty:** Han et al. describe consistency as a conceptual requirement. This project implements it via the Protected Policy Layer, immutable state boundaries, and session-sticky routing in a production-style containerized platform.

#### Source 6: [LIT-06] Cho et al. (2020)
- **Full Citation:** Cho, J.-H., Sharma, D. P., Alavizadeh, H., Yoon, S., Ben-Asher, N., Moore, T. J., Ahmad, R., & Nelson, H. (2020). Toward Proactive, Adaptive Defense: A Survey on Moving Target Defense. *IEEE Communications Surveys & Tutorials*, Vol. 22, No. 1, pp. 709–745.  
- **DOI:** [10.1109/COMST.2019.2954091](https://doi.org/10.1109/COMST.2019.2954091)
- **Problem & Proposed Approach:** Asymmetry in cyber warfare favors attackers who have unlimited time to probe static defenses. The authors surveyed Moving Target Defense (MTD) as a mechanism to dynamically shift attack surfaces.
- **Key Technical Mechanisms:** Shuffling (IP/port address hopping), diversity (multi-compiler binaries), and dynamic redundancy across software, network, and data stacks.
- **Evaluation Method & Limitations:** Exhaustive review of 200+ MTD schemes, analyzing effectiveness models and trade-offs in deployment complexity. Limitations: MTD often introduces high performance overhead, service disruption, and synchronization challenges for legitimate users.
- **Direct Project Overlap:** Shares the core philosophy of proactive, adaptive defense rather than passive perimeter filtering.
- **Project Differences & Novelty:** MTD continuously alters legitimate infrastructure, risking operational stability. This project keeps the legitimate origin static and changes only the routing destination for malicious sessions, isolating operational risk to the attacker.

#### Source 7: [LIT-07] Sengupta et al. (2020)
- **Full Citation:** Sengupta, S., Chowdhary, A., Sabur, A., Al-Shaer, E., & Kambhampati, S. (2020). A Survey of Moving Target Defenses for Network Security. *IEEE Communications Surveys & Tutorials*, Vol. 22, No. 3, pp. 1909–1941.  
- **DOI:** [10.1109/COMST.2020.2982955](https://doi.org/10.1109/COMST.2020.2982955)
- **Problem & Proposed Approach:** Network-level reconnaissance and lateral movement enable persistent adversaries to compromise enterprise systems. The authors analyzed network MTD mechanisms.
- **Key Technical Mechanisms:** Explored Software-Defined Networking (SDN) for dynamic OpenFlow flow routing, IP hopping, honey-patching, and game-theoretic defense planning.
- **Evaluation Method & Limitations:** Systematic survey focusing on formal verification, game-theoretic optimality, and testbed experiments. Limitations: Heavy reliance on SDN network infrastructure, OpenFlow switch state limits, and flow-table churn.
- **Direct Project Overlap:** Studies dynamic routing away from critical assets toward decoy nodes.
- **Project Differences & Novelty:** Sengupta et al. concentrate on Layer-3/Layer-4 network flow steering. This project operates as an application-layer (L7) HTTP reverse proxy with cryptographic DNS TXT tenant onboarding and multi-tenant isolation.

#### Source 8: [LIT-08] Torrano-Giménez, Pérez-Villegas, & Álvarez Marañón (2010)
- **Full Citation:** Torrano-Giménez, C., Pérez-Villegas, A., & Álvarez Marañón, G. (2010). An anomaly-based approach for intrusion detection in web traffic. *Journal of Information Assurance and Security*, Vol. 5, No. 4, pp. 446–454.  
- **Canonical URL:** [CSIC Dataset Portal](http://www.isi.csic.es/dataset/)
- **Problem & Proposed Approach:** Lack of realistic public HTTP test datasets containing structured web parameters and automated attack payloads for anomaly detection benchmarking.
- **Key Technical Mechanisms:** Created the CSIC 2010 dataset by recording automated web crawler traffic (normal) and automated penetration testing scans via Paros proxy and Nessus (anomalous) against an experimental e-commerce application ("tienda1").
- **Evaluation Method & Limitations:** Evaluated clustering algorithms and anomaly detection classifiers. Limitations: Traffic generated by automated tools rather than live human attackers; dated HTTP/1.1 syntax; lacks multi-turn session state.
- **Direct Project Overlap:** Source of 69 out of 100 scenarios in this project's external benchmark dataset (`data/scenarios/external_benchmark_v1.json`).
- **Project Differences & Novelty:** Torrano-Giménez et al. used the dataset for offline anomaly classification. This project integrates these requests into an end-to-end gateway evaluation measuring physical origin leakage and session routing behavior.

#### Source 9: [LIT-09] Vetterl & Clayton (2019)
- **Full Citation:** Vetterl, A., & Clayton, R. (2019). Honware: A Virtual Honeypot Framework for Capturing CPE and IoT Zero Days. In *Proceedings of the 2019 APWG Symposium on Electronic Crime Research (eCrime)*, pp. 1–13, Pittsburgh, PA, USA.  
- **DOI:** [10.17863/CAM.46510](https://doi.org/10.17863/CAM.46510)
- **Problem & Proposed Approach:** Manual creation of web honeypots is unscalable, while low-interaction honeypots are easily fingerprinted and discarded by automated worm/scanner botnets.
- **Key Technical Mechanisms:** Developed *Honware*, an automated system that unpacks firmware images, extracts web application components, and dynamically instantiates responsive virtual web honeypots.
- **Evaluation Method & Limitations:** Large-scale Internet deployment capturing zero-day IoT exploits. Limitations: Emulates complete embedded Linux systems; resource-heavy; focused on Internet-wide opportunistic malware rather than targeted web enterprise attacks.
- **Direct Project Overlap:** Highlights the necessity of stateful, valid HTTP response generation to maintain attacker engagement.
- **Project Differences & Novelty:** Honware targets firmware emulation for IoT honeypots. This project focuses on an enterprise multi-tenant reverse proxy gateway defending authorized corporate origins.

#### Source 10: [LIT-10] Robertson et al. (2006)
- **Full Citation:** Robertson, C., Vigna, G., Kruegel, C., & Kemmerer, R. (2006). Using Generalization and Characterization to Detect Web-Based Attacks. In *Proceedings of the 13th Network and Distributed System Security Symposium (NDSS 2006)*, San Diego, CA, USA.  
- **Stable URL:** [NDSS Symposium Archive](https://www.ndss-symposium.org/ndss2006/using-generalization-and-characterization-detect-web-based-attacks/)
- **Problem & Proposed Approach:** Anomaly-based web IDSs trigger unacceptable volumes of false positives because legitimate web users access parameters in unforeseen but benign ways.
- **Key Technical Mechanisms:** Introduced structural generalization: anomaly alerts are grouped by parameter structure and characterized using signature-based filters to confirm attacks while suppressing benign novel variations.
- **Evaluation Method & Limitations:** Evaluated over millions of requests on live university web portals. Limitations: Purely a detection mechanism; cannot contain an attacker once detected.
- **Direct Project Overlap:** Addresses the false-positive dilemma observed in Stage 10 adversarial testing (where benign requests with SQL keywords triggered 40.5% FPR in pure ML mode).
- **Project Differences & Novelty:** Robertson et al. attempted to solve the problem by refining alert thresholds. This project handles uncertainty structurally via the `OBSERVE_ONLY` routing mode, which safely allows ambiguous traffic to reach the origin while escalating surveillance.

---

## 4. Scholarly Comparison Matrix

The following matrix compares this project against the canonical scholarly literature across eight core dimensions:

| Dimension | [LIT-01] Anagnostakis et al. (2005) | [LIT-02] Kruegel & Vigna (2003) | [LIT-03] Pawlick et al. (2019) | [LIT-04] Ferguson-Walter (2021) | [LIT-05] Han et al. (2018) | [LIT-07] Sengupta et al. (2020) | **This Project (Gateway + DSG)** |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Detection Approach** | Anomaly detection on network payloads | Statistical feature models (length, entropy, tokens) | Abstract threat signal / sensor input | Red-team observation / host sensors | Multi-source IDS / tripwire triggers | SDN flow monitors / snort alerts | **Hybrid:** L7 feature extractor + Random Forest + Regex short-circuits |
| **Behavioral Profiling** | None (per-request execution) | None (stateless request evaluation) | Bayesian belief state updates | Qualitative operator profiling | Attacker TTP classification | Attack graph traversal tracking | **Session-Aware Context:** Rolling auth failures, request rates, decoy taps |
| **Adaptation Mechanism** | Selective diversion to shadow process | None (passive alerting) | Strategic game-theoretic equilibrium | Psychological priming & decoy scaling | Dynamic decoy reconfiguration | SDN flow table mutation | **Policy Controller:** Score thresholding, shadow/active modes, killswitch |
| **Deception State Representation** | Application process memory clone | None | Game-theoretic information sets | Network subnets & physical decoys | Multi-layer decoy taxonomy | Network topology attack graphs | **Deception State Graph (DSG):** 4-node finite state machine |
| **Cross-Service Consistency** | Complete (mirrors live process state) | N/A | Theoretical game consistency | Real enterprise host emulation | Systemic consistency principle | Protocol & address consistency | **Protected Policy Layer:** Immutable allowlist, synthetic JSON schemas |
| **Session Continuity** | Request-level rollback | None | Multi-stage dynamic games | Multi-day red-team engagement | Session-level honeypot binding | OpenFlow sequence tracking | **Session Stickiness:** Sliding TTL store (`sess_*` cookie/header) |
| **Evaluation Methodology** | Prototype on Apache/Firefox with exploits | DARPA 1999 + University web traces | Mathematical proofs & taxonomies | Empirical human trial (130+ operators) | Qualitative systematic review | Game simulations & SDN testbeds | **Empirical Benchmark:** 120 synthetic + 70 robust + 100 external |
| **Reported Limitations** | Process cloning overhead, rollback limits | High false positives on new parameters | Scalability (curse of dimensionality) | High experimental cost, human variance | Lack of unified architecture | Switch flow table capacity, SDN latency | **Limited Generalization:** Single-turn public data limits, 26% leakage |

---

## 5. Critical Analysis: Evasion, Overhead, and False-Positive Tradeoffs

The synthesis of prior literature illuminates three fundamental tensions present in cyber deception platforms:

### 5.1 The Anomaly Detection vs. Evasion Trade-off
As established by Kruegel & Vigna (2003) and Robertson et al. (2006), feature-based anomaly detection operates on statistical deviations. Persistent attackers aware of an anomaly gateway can evade detection by:
- **Low-and-Slow Probing:** Distributing requests across time to keep request frequency low.
- **Syntactic Conformance:** Camouflaging injection payloads within benign parameter distributions (e.g. blind boolean SQLi using short alphanumeric queries).
- **Adversarial Encoding:** Utilizing multi-layer URL encoding, unicode normalization, or alternative comment syntaxes (as observed in Stage 10 adversarial testing, where novel templates produced a 51.5% False Negative Rate).

*Project Resolution:* The project mitigates pure ML evasion through deterministic regex fast-paths and behavioral history accumulation (`auth_failure_count`, `request_frequency`), but our Stage 10 and 11 results explicitly confirm that evasion remains a defensible boundary limitation.

### 5.2 The False Positive vs. Denial-of-Service Trade-off
In traditional inline prevention (e.g., standard WAFs), a false positive results in an immediate service outage for legitimate users. Anagnostakis et al. (2005) solved this by cloning memory and executing false positives on shadow clones. 
In this project, a false positive diverts a legitimate user into a synthetic honeypot. While this prevents attacker disruption of the origin, it causes user confusion and transactional failure (e.g., a legitimate customer checkout hitting `/api/catalog` on the deception mock). 

*Project Resolution:* The project introduces the `OBSERVE_ONLY` state for intermediate risk scores ($0.40 \le score < 0.70$) and provides an `EMERGENCY_DISABLE_DIVERSION` killswitch. Furthermore, in Stage 11 external testing on 50 benign CSIC 2010 requests, the system achieved **0.0% False Positive Rate (100% Specificity)**, demonstrating that standard browsing parameters are not diverted under normal operating conditions.

### 5.3 Deployment Overhead & Latency Budgets
Inline deception gateways must process requests within acceptable user latency budgets. The empirical measurements documented in Stage 10 and 11 demonstrate:
- **Direct Passthrough (B1):** 0.2 µs
- **Static Substring (B2):** 0.4 µs
- **Regex Rules (B3 / Variant B):** 0.016 ms (16 µs)
- **Full Proposed Gateway (B4 / Variant A):** 13.587 ms p50 latency (dominated by the Python ML inference boundary, feature scaling, and random forest tree traversal)

While 13.6 ms is well within acceptable web application response budgets (< 100 ms), it represents a $1000\times$ latency increase over pure regex rules. This trade-off must be explicitly acknowledged when positioning the architecture for high-throughput enterprise deployment.

---

## 6. Conclusion

The academic literature validates the core architectural principles of the AI-Enabled Adaptive Cyber Deception Gateway:
1. Selective anomaly diversion is a recognized mechanism for mitigating the operational risks of static blocking (Anagnostakis et al. 2005).
2. Attacker dwell time, decoy engagement, and containment are scientifically grounded metrics of defensive efficacy (Ferguson-Walter et al. 2021).
3. Session persistence and state consistency are mandatory to prevent deception fingerprinting (Han et al. 2018).

At the same time, the literature confirms that claims of universal generalization or autonomous AI deception cannot be substantiated without extensive multi-turn human red-team testing. The project's contributions are therefore rigorously framed as an application-layer integration, policy routing framework, and empirical evaluation benchmark.
