# Patent Prior-Art Investigation: Adaptive Cyber Deception, Dynamic Traffic Diversion, and Stateful Orchestration

> **Document Type:** Patent Prior-Art Search & Technical Element Claim Matrix  
> **Project:** AI-Enabled Adaptive Cyber Deception Gateway for Real-Time Attacker Detection  
> **Repository Commit:** `fa9960205ecc00a952b3f64bdf1125b608d8370b`  
> **Search Execution Date:** October 19, 2026  
> **Databases Queried:** Google Patents, WIPO PATENTSCOPE, Espacenet (EPO), USPTO Patent Public Search  
> **Status:** Stage 12 Preliminary Patent Investigation  

---

## 1. Executive Notice & Legal Disclaimer

> [!CAUTION]
> **Legal Disclaimer:** This document is a technical prior-art investigation prepared for academic research and software engineering evaluation. It **does not constitute a formal legal opinion**, patentability opinion, or freedom-to-operate (FTO) analysis. The presence, absence, or categorization of patent documents herein does not determine whether any claim is valid, enforceable, infringed, or novel. Legal determinations under patent statutes (such as the Indian Patents Act, 1970, 35 U.S.C. in the United States, or the European Patent Convention) must be conducted by a registered patent agent or intellectual property attorney.

---

## 2. Patent Prior-Art Search Strategy & Methodology

### 2.1 Scope and Objective
The search was designed to identify granted patents and published patent applications that intersect the core technical mechanisms of the project:
1. **Dynamic / adaptive traffic diversion** from production targets to decoy/honeypot environments based on anomaly detection or risk scoring.
2. **Stateful deception orchestration** using state machines, state graphs, or progressive interaction stages.
3. **Session-aware containment and persistence** in web-facing honeypots.
4. **Consistency constraints and protected policy controls** within deception environments.
5. **Deception efficacy metrics, scoring algorithms, and evidence-based measurement.**

### 2.2 Search Queries and Classification Codes
Search formulations were executed across Google Patents, Espacenet, and WIPO PATENTSCOPE targeting:
- **Cooperative Patent Classification (CPC) Codes:**
  - `H04L 63/14` (Detection or handling of malicious traffic, network intrusion)
  - `H04L 63/1491` (Deception systems, honeypots, decoys)
  - `H04L 63/02` (Network gateways, firewalls, proxies)
  - `G06F 21/55` (Detecting local or system intrusions)
- **Keyword Strings:**
  - `("adaptive cyber deception" OR "dynamic honeypot") AND ("traffic diversion" OR "reverse proxy" OR "redirect")`
  - `("deception state graph" OR "state machine") AND ("honeypot" OR "decoy") AND ("consistency" OR "policy")`
  - `("threat score" OR "anomaly score") AND ("session stickiness" OR "session persistence") AND ("deception")`
  - `("dwell time" OR "deception effectiveness") AND ("scoring" OR "metric") AND ("honeypot")`

---

## 3. Detailed Review of Canonical Patent Documents

Eight highly relevant patent documents from prominent deception technology assignees (Acalvio, Attivo/SentinelOne, Illusive/Proofpoint, TrapX, NSA, and National Laboratories) were selected for deep-dive technical element mapping.

---

### 3.1 [PAT-01] US Patent No. 10,193,924 B2
- **Title:** *Network intrusion diversion using a software defined network*
- **Assignee:** Acalvio Technologies, Inc. (Santa Clara, CA, USA)
- **Inventors:** Johnson L. Wu, Catherine V.
- **Priority Date:** September 8, 2015 | **Filing Date:** September 8, 2015 | **Grant Date:** January 29, 2019
- **Official Link:** [Google Patents US10193924B2](https://patents.google.com/patent/US10193924B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A method comprising: receiving network packets directed to a physical computer on an enterprise network; determining an intrusion attempt based on the network packets; utilizing a software defined network (SDN) controller to divert subsequent network packets from the physical computer to a decoy software-based host emulator having the exact same IP address as the physical computer; and executing the subsequent network packets on the decoy software-based host emulator."*
- **Technical Overlap with Project:**
  - Establishes the foundational concept of dynamically diverting packets from an authentic production computer to a decoy emulator upon detecting an intrusion attempt.
- **Technical Distinctions & Structural Differences:**
  - **Network Layer:** US 10,193,924 operates at Layer 3/Layer 4 (network packets, IP address cloning, and OpenFlow SDN switch flow-table modifications). This project operates at Layer 7 (HTTP application layer) as a reverse proxy gateway.
  - **Identity & Addressing:** US 10,193,924 clones the exact IP address of the physical host on an SDN switch. This project routes HTTP requests based on application-level session tokens (`sess_*` cookies/headers) to an unexposed, isolated container backend over Docker bridge networks.
  - **State Representation:** US 10,193,924 uses a full host OS/software emulator. This project uses a 4-node finite state graph (DSG) managing synthetic mock APIs.

---

### 3.2 [PAT-02] US Patent No. 9,979,750 B2 (and continuation US 11,212,315 B2)
- **Title:** *Tunneling for network deceptions*
- **Assignee:** Acalvio Technologies, Inc.
- **Inventors:** Johnson Wu, Sreenivas Gukal, Rammohan Varadarajan
- **Priority Date:** April 26, 2016 | **Filing Date:** April 26, 2016 | **Grant Date:** May 22, 2018
- **Official Link:** [Google Patents US9979750B2](https://patents.google.com/patent/US9979750B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A system comprising: a first network device on a first network configured as a projection point for a network tunnel terminating at a deception center on a second network; wherein the deception center assigns an IP address from the first network to a deception mechanism in the deception center, such that network traffic directed to the assigned IP address is tunneled through the network tunnel to the deception mechanism."*
- **Technical Overlap with Project:**
  - Isolates the deception execution environment into a dedicated secondary network while projecting deceptive assets into the primary operational topology.
- **Technical Distinctions & Structural Differences:**
  - US 9,979,750 claims network tunneling (e.g. GRE or IPsec tunnels) and IP address projection to plant dark-subnet decoys across enterprise subnets.
  - This project uses an application-layer reverse proxy that terminates HTTP/TLS connections and performs Layer-7 path rewrites to internal container hosts without network tunneling or dark-IP synthesis.

---

### 3.3 [PAT-03] US Patent No. 10,348,763 B2
- **Title:** *Responsive deception mechanisms*
- **Assignee:** Acalvio Technologies, Inc.
- **Inventors:** Johnson Wu, Rajendra Arcot Gopalakrishna, Suril Desai
- **Priority Date:** December 1, 2016 | **Filing Date:** December 1, 2016 | **Grant Date:** July 9, 2019
- **Official Link:** [Google Patents US10348763B2](https://patents.google.com/patent/US10348763B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A method comprising: deploying a plurality of low-interaction deception mechanisms in a network; detecting an initial interaction with a first low-interaction deception mechanism; in response to detecting the initial interaction, dynamically deploying a high-interaction deception mechanism to replace or augment the first low-interaction deception mechanism; and migrating the connection to the high-interaction deception mechanism."*
- **Technical Overlap with Project:**
  - Escalates deception detail and interactive capability in response to detected adversary progression.
- **Technical Distinctions & Structural Differences:**
  - US 10,348,763 escalates physical or virtual machine infrastructure (spinning up a full high-interaction VM from a low-interaction trap).
  - This project modulates observation detail, response delay, and honeytoken injection within a single Node.js runtime across finite states (`RECONNAISSANCE` $\rightarrow$ `DISCOVERY` $\rightarrow$ `EXPLOITATION` $\rightarrow$ `CREDENTIAL_ACCESS`).

---

### 3.4 [PAT-04] US Patent No. 10,375,110 B2
- **Title:** *Luring attackers towards deception servers*
- **Assignee:** Attivo Networks, Inc. (Acquired by SentinelOne)
- **Inventors:** Venu Vissamsetty, Srikant Vissamsetti, Shivakumar Buruganahalli
- **Priority Date:** October 26, 2016 | **Filing Date:** October 26, 2016 | **Grant Date:** August 6, 2019
- **Official Link:** [Google Patents US10375110B2](https://patents.google.com/patent/US10375110B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A system comprising: network endpoints configured to establish payload-free connections with a deception server to populate local connection caches; a deception server configured to acquire IP addresses across multiple virtual local area networks (VLANs); and a broadcast generator configured to transmit artificial broadcast traffic enticing attackers on the endpoints to query the deception server."*
- **Technical Overlap with Project:**
  - Diverts threat actors toward dedicated deception servers to safeguard production assets.
- **Technical Distinctions & Structural Differences:**
  - US 10,375,110 lures attackers via endpoint breadcrumbs, ARP/VLAN cache manipulation, and synthetic NetBIOS/broadcast traffic.
  - This project is an inline HTTP reverse proxy gateway. It does not manipulate client endpoints, local caches, or broadcast traffic; it directly evaluates inbound HTTP requests and diverts the network session at ingress.

---

### 3.5 [PAT-05] US Patent No. 10,333,977 B1
- **Title:** *Deceiving an attacker who is present in a computer network*
- **Assignee:** Illusive Networks Ltd. (Acquired by Proofpoint)
- **Inventors:** Tomer Shamul, Tsahi Lasry, Moshe Segev, Mor Natan
- **Priority Date:** August 23, 2018 | **Filing Date:** August 23, 2018 | **Grant Date:** June 25, 2019
- **Official Link:** [Google Patents US10333977B1](https://patents.google.com/patent/US10333977B1/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A method comprising: deploying deceptive credentials and deceptive connection artifacts into memory or storage of a plurality of endpoint computers; detecting when an attacker present in the network attempts to harvest or utilize said deceptive credentials; and generating an alert identifying the compromised endpoint."*
- **Technical Overlap with Project:**
  - Utilization of deceptive credentials and authentication challenges to trap malicious actors.
- **Technical Distinctions & Structural Differences:**
  - US 10,333,977 is an endpoint deception system focused on planting fake credentials (e.g. LSASS memory tokens, Kerberos tickets, RDP cache) on Windows workstations.
  - This project is an application-layer web proxy. It injects honeytokens into HTTP responses and provides synthetic web authentication endpoints (`/api/auth/login`) without endpoint software.

---

### 3.6 [PAT-06] US Patent No. 11,934,948 B2
- **Title:** *Adaptive deception system*
- **Assignee:** The United States of America as represented by the Director, National Security Agency (NSA)
- **Inventors:** Ronald I. Routh, David J. Mountain
- **Priority Date:** May 12, 2021 | **Filing Date:** May 12, 2021 | **Grant Date:** March 19, 2024
- **Official Link:** [Google Patents US11934948B2](https://patents.google.com/patent/US11934948B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"An adaptive deception system comprising: an observation module configured to monitor entity interactions with network nodes; a scoring module configured to generate a risk score based on entity interaction patterns; a deception decision engine configured to adaptively alter deception profiles assigned to the entity; and an orchestration module configured to dynamically reconfigure network decoys based on said deception profiles."*
- **Technical Overlap with Project:**
  - Direct functional overlap with risk scoring, behavioral profiling, and adaptive deception reconfiguration.
- **Technical Distinctions & Structural Differences:**
  - US 11,934,948 is an enterprise-wide network orchestration architecture reconfiguring multi-node decoy networks.
  - This project implements an inline reverse proxy gateway coupling request-level ML inference, sticky session routing, and a mathematically gated Deception Effectiveness Score (DES) measuring physical origin leakage.

---

### 3.7 [PAT-07] US Patent Application Publication No. 2017/0134423 A1
- **Title:** *Decoy and deceptive data object technology*
- **Applicant:** TrapX Security, Inc. (Acquired by Commvault)
- **Inventor:** Imri Goldberg
- **Priority Date:** November 10, 2015 | **Filing Date:** November 10, 2015 | **Publication Date:** May 11, 2017
- **Official Link:** [Google Patents US20170134423A1](https://patents.google.com/patent/US20170134423A1/en)
- **Legal Status:** Published Patent Application
- **Claim Focus:**
  - Deploying deceptive data objects (bait documents, fake database credentials) onto file shares; upon unauthorized access, dynamically standing up a decoy virtual machine or service emulator to trap the lateral mover.
- **Technical Overlap & Distinctions:**
  - TrapX focuses on bait files and file-share tripwires. This project intercepts web application HTTP traffic at ingress.

---

### 3.8 [PAT-08] US Patent No. 11,876,833 B2
- **Title:** *Software Defined Networking Moving Target Defense Honeypot*
- **Assignee:** UChicago Argonne, LLC (Argonne National Laboratory)
- **Inventors:** Nathaniel Evans, Eugene Golovchenko, Cheryl Rogers
- **Priority Date:** July 17, 2020 | **Filing Date:** July 17, 2020 | **Grant Date:** January 16, 2024
- **Official Link:** [Google Patents US11876833B2](https://patents.google.com/patent/US11876833B2/en)
- **Legal Status:** Granted Patent (Active)
- **Independent Claim Analysis (Claim 1):**
  > *"A moving target defense honeypot system comprising: an SDN switch; an SDN controller configured to receive flow rules; a threat detection module configured to identify anomalous traffic flows; wherein the SDN controller modifies switch flow tables to route anomalous flows to an adaptive honeypot while routing non-anomalous flows to an operational network target."*
- **Technical Overlap with Project:**
  - Directly matches the high-level routing concept: non-anomalous flows go to operational origin, anomalous flows go to an adaptive honeypot.
- **Technical Distinctions & Structural Differences:**
  - US 11,876,833 requires an OpenFlow/SDN controller and switch hardware manipulating packet headers and flow tables at L3/L4. This project is implemented as an L7 Node.js reverse proxy with multi-tenant domain verification and session cookie routing.

---

## 4. Patent-Element Comparison Matrix

To analyze patentability and prior-art density, the implemented gateway platform is decomposed into seven specific technical elements:

```
[E1] Layer-7 Reverse Proxy with Multi-Tenant Domain Verification (DNS TXT challenge)
[E2] Hybrid Anomaly Detection Pipeline (RandomForest + Regex Fast-Paths + Feature Extractor)
[E3] Policy Decision Controller with Intermediate 'OBSERVE_ONLY' Origin Forwarding
[E4] Stateful Session Router with In-Memory Sticky Session Pinning to Deception
[E5] Deception State Graph (DSG) Finite State Machine (4-node progression)
[E6] Protected Policy Layer with Allowlisted Synthetic REST Services
[E7] Evidence-Based Deception Effectiveness Score (DES) with Binary Zero-Leak Gate
```

### Claim-by-Element Prior-Art Mapping

| Technical Element | [PAT-01] US10193924 (Acalvio) | [PAT-02] US9979750 (Acalvio) | [PAT-03] US10348763 (Acalvio) | [PAT-04] US10375110 (Attivo) | [PAT-06] US11934948 (NSA) | [PAT-08] US11876833 (Argonne) | Prior-Art Assessment & Novelty Analysis |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **[E1] L7 Proxy & Multi-Tenant DNS TXT** | No (L3/L4 SDN) | No (L3 Tunnel) | No (VM Decoy) | No (VLAN/ARP) | No (General Node) | No (OpenFlow SDN) | **Established Web Standard:** DNS TXT verification is standard (ACME/RFC 8555); proxying is standard reverse-proxy art. Combination with deception is an application engineering integration. |
| **[E2] Hybrid ML + Regex Scoring** | Yes (Generic IDS) | No | Yes (Sensor) | Yes (Detection) | Yes (Threat Scoring) | Yes (Anomaly Module) | **Established Prior Art:** Combining ML classifiers with regex signature fast-paths is standard in commercial WAFs and published IDS literature. |
| **[E3] Policy Controller with `OBSERVE_ONLY`** | No (Binary Divert) | No | No (Escalation) | No | Yes (Profiles) | No (Binary Flow) | **Partially Distinct Combination:** Prior art predominantly executes binary diversion. Forwarding ambiguous traffic to origin while counting malicious slips as origin leaks is an evaluation and policy nuance. |
| **[E4] Cookie-Pinned Session Stickiness** | No (Packet flow) | No | No | No | No (Node-based) | No (TCP flow) | **Established in Web Art / Novel in Deception:** Session stickiness is ubiquitous in HTTP load balancing (e.g. AWS ALB, NGINX), but its application as a containment trap for multi-turn web honeypots is less common in patent claims. |
| **[E5] Deception State Graph (DSG)** | No (Emulators) | No | Yes (Low-to-High) | No | Yes (Deception Profile) | No (Decoy Node) | **Known in Theory / Specific in Implementation:** State machine modeling of attacker progression is well-known in academic attack graphs. The specific 4-node FSM (`RECON` $\rightarrow$ `CRED_ACCESS`) is an implementation choice. |
| **[E6] Protected Policy Layer** | No | No | No | No | Yes (Guard rules) | No | **Software Security Invariant:** Restricting container capabilities and allowlisting APIs is established defensive engineering (e.g. zero-trust API gateways). |
| **[E7] Zero-Leak Gated DES Metric** | No | No | No | No | No (Heuristic) | No | **Potentially Distinguishing Evaluation Method:** The mathematical gate $\mathbb{I}[L_{\text{leak}} = 0]$ collapsing deception effectiveness to zero upon any origin leak is unique to this project's research framework, though mathematical algorithms alone face patentability hurdles under 35 U.S.C. 101 and Section 3(k) of the Indian Patents Act. |

### 4.1 Prior-Art Density Assessment
- **Established Components:** Dynamic diversion of attack traffic to honeypots ([PAT-01], [PAT-08]), progressive deception escalation ([PAT-03], [PAT-06]), and threat scoring ([PAT-06]) are **heavily patented by enterprise vendors**.
- **Combination Defense:** An applicant cannot claim "diverting suspicious network traffic to a honeypot" broadly. Any potential claims would need to be narrowly directed to the specific combination of Layer-7 cookie-pinned session persistence, the multi-state DSG traversal mechanism, and the zero-leak policy gate.
- **Obviousness / Inventive Step Risks:** A patent examiner under 35 U.S.C. 103 (US) or Section 2(1)(ja) (India) would likely argue that combining an L7 reverse proxy (standard HTTP load balancer) with an anomaly detector (standard WAF) and a containerized mock API (standard honeypot) represents a predictable combination of known elements yielding predictable results.

---

## 5. Public-Disclosure Timeline & Legal Considerations

### 5.1 Public Disclosure Audit
The repository is publicly hosted on GitHub at:  
`https://github.com/TheCreativeCodeFlow/AI-Enabled-Adaptive-Cyber-Deception-Gateway-for-Real-Time-Attacker-Detection`

The git commit audit establishes the following public disclosure timeline:

| Commit Hash | Timestamp (ISO 8601) | Disclosure Event & Content |
| :--- | :--- | :--- |
| `5520d59` | **2026-10-17 22:40:18 +0530** | **Earliest Verifiable Public Commit:** Initial repository push containing architecture documentation, system specifications, and core gateway foundations. |
| `89d31ea` | 2026-10-17 23:21:17 +0530 | Reverse proxy gateway implementation and test origin. |
| `6195d72` | 2026-10-18 21:09:50 +0530 | ML detection engine, schemas, and shadow mode integration. |
| `05b56db` | 2026-10-18 21:26:27 +0530 | Isolated deception runtime and Deception State Graph (DSG) implementation. |
| `60aa4de` | 2026-10-18 21:51:48 +0530 | Policy-controlled traffic diversion and decision controller. |
| `2ed8a91` | 2026-10-18 22:37:38 +0530 | Multi-tenant organization management, DNS TXT verification, and application onboarding. |
| `757f598` | 2026-10-19 13:52:52 +0530 | Benchmark dataset v1 (120 scenarios), model artifact `model.joblib`, and baseline results. |
| `b63ba15` | 2026-10-19 14:38:20 +0530 | Adversarial robustness dataset (70 scenarios) and multi-variant ablation study. |
| `39bab2c` | 2026-10-19 18:02:04 +0530 | External benchmark validation (100 scenarios) and routing semantics audit. |
| `fa99602` | **2026-10-19 18:57:44 +0530** | Source-to-scenario provenance metadata, rights verification, and legal terms audit. |

### 5.2 Legal Implications by Jurisdiction

#### 1. India (The Patents Act, 1970)
- **Absolute Novelty Principle:** Under Indian patent law, an invention must not have been publicly disclosed or anticipated by prior public knowledge anywhere in the world prior to the filing date.
- **Section 29–34 Exceptions & Limitations:** The Indian Patents Act provides very narrow exceptions to prior public disclosure:
  - **Section 31:** Allows a 12-month grace period *only* if the disclosure occurred at an industrial or other exhibition notified by the Central Government, or by reading a paper before a learned society.
  - **Informal GitHub Publication:** Making a repository public on GitHub **does not fall under Section 31 exceptions**. Public hosting on GitHub constitutes prior public disclosure ("anticipation by public display") that destroys absolute novelty in India unless a provisional application was already on file prior to October 17, 2026.
- **Section 3(k) Exclusion:** Under Indian law, "a mathematical method or a business method or a computer programme per se or algorithms" are non-patentable subject matter. Software-implemented inventions must demonstrate a technical effect or technical advancement that modifies hardware functionality.

#### 2. United States (35 U.S.C. § 102)
- **1-Year Grace Period (35 U.S.C. § 102(b)(1)):** The United States provides a 1-year inventor grace period. A public disclosure made by the inventor within 1 year before the US effective filing date does not qualify as prior art against the inventor's application.
- **Deadline:** Because the earliest public commit occurred on **October 17, 2026**, any US provisional or utility application relying on this grace period must be filed on or before **October 17, 2027**.

#### 3. Europe (European Patent Convention — EPC)
- **EPC Article 54(2) Absolute Novelty:** The EPC applies strict absolute novelty. Any disclosure made available to the public anywhere in the world before the filing date forms part of the state of the art.
- **EPC Article 55 Exceptions:** Non-prejudicial disclosures are restricted exclusively to evident abuse in relation to the applicant or display at official international exhibitions. Public GitHub repository commits constitute novelty-destroying prior art in Europe.

---

## 6. Questions and Evidence for an Indian Patent Professional

When consulting an Indian patent agent or intellectual property attorney, the following factual evidence and specific legal questions should be presented:

### Evidence Portfolio to Provide
1. **Repository Commit Log:** Exact timestamped git commit history proving the exact date of first public commit (`October 17, 2026, 22:40:18 +0530`).
2. **Access Telemetry:** Evidence regarding whether the repository was indexed, cloned, starred, or accessed by third parties between October 17 and the consultation date.
3. **Prior Private Commits / Drafts:** Any prior non-public documentation, local timestamps, or private development logs predating October 17, 2026.
4. **Source Code Architecture:** Complete structural code and architecture specifications (`docs/architecture.md`).

### Questions for Patent Counsel
1. **Novelty Bar in India:** *Does the public release of the source code on GitHub on October 17, 2026, constitute an incurable anticipation under Sections 29–34 of the Indian Patents Act, 1970, or does any exception apply?*
2. **Section 3(k) Guidelines:** *Given the revised Guidelines for Examination of Computer-Related Inventions (CRIs), does the interaction between the Layer-7 reverse proxy gateway and the containerized deception runtime demonstrate sufficient "technical effect" (e.g. network protection, physical origin isolation) to overcome the Section 3(k) exclusion on software algorithms?*
3. **PCT / US Paris Convention Filing Strategy:** *Given that the United States provides a 1-year grace period under 35 U.S.C. 102(b)(1), is it legally viable to file a US application (or PCT application designating the US) prior to October 17, 2027, even if Indian rights are impaired by public disclosure?*
4. **Distinguishing Subject Matter:** *Which specific combinations—such as the cookie-pinned session router coupled with the finite-state DSG and zero-leak gated metrics—present the most defensible inventive step over Acalvio US 10,193,924 and Argonne US 11,876,833?*
5. **Trade Secret vs Open Source:** *Given the complete transparency of the GitHub repository, should the project continue under an open-source research and defensible publication model (protecting against patent trolls via prior-art defensive publication) rather than pursuing costly patent prosecution?*

---

## 7. Preliminary Conclusion

1. **Prior-Art Saturation:** The broad concept of anomaly-triggered diversion of network traffic into honeypots is well-established in granted patents ([PAT-01], [PAT-08]).
2. **Distinguishing Features:** The project's differentiating nuances lie in its Layer-7 session persistence (`sessionId` cookie-pinning), the 4-node DSG finite state progression, and the mathematical DES formulation enforcing zero origin leakage.
3. **Public Disclosure Impact:** The public GitHub repository created on October 17, 2026, represents a prior public disclosure that impairs patentability in absolute novelty jurisdictions (India, Europe), while triggering a 1-year statutory clock in the United States.
4. **Strategic Recommendation:** Prioritize **open scientific publication and defensive disclosure**. By thoroughly documenting and publishing the architecture, benchmarks, and ablation studies, the project establishes verifiable prior art that prevents third-party commercial entities from patenting these Layer-7 deception gateway techniques against the open-source community.
